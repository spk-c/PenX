"""Installer rollback and BAT exit-code regressions for issue #62 (no installs)."""
import subprocess
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import windows_python_setup as setup

ROOT = Path(__file__).resolve().parents[1]


class RollbackTests(unittest.TestCase):
    def test_failed_environment_creation_restores_backup_with_unicode_space_path(self):
        with tempfile.TemporaryDirectory(prefix="PenX Ünicode ") as tmp:
            root = Path(tmp)
            env = root / ".venv"
            interpreter = env / "Scripts" / "python.exe"
            interpreter.parent.mkdir(parents=True)
            interpreter.write_text("old interpreter", encoding="utf-8")
            (root / ".env").write_text("private data", encoding="utf-8")
            (root / "data").mkdir()
            (root / "data" / "scan.db").write_bytes(b"private")
            def fail_run(argv, **kwargs):
                # A failed venv creation can leave partial new files behind.
                (env / "Scripts").mkdir(parents=True, exist_ok=True)
                (env / "Scripts" / "python.exe").write_text("partial", encoding="utf-8")
                return subprocess.CompletedProcess(argv, 1)
            with patch.object(setup, "ROOT", root), patch.object(setup, "VENV", env), \
                 patch.object(setup, "PYTHON_VENV", interpreter), \
                 patch.object(setup, "python_version", return_value=(3, 15)), \
                 patch.object(setup, "run", side_effect=fail_run):
                self.assertFalse(setup.ensure_venv(["python"]))
            self.assertEqual(interpreter.read_text(encoding="utf-8"), "old interpreter")
            self.assertEqual((root / ".env").read_text(encoding="utf-8"), "private data")
            self.assertEqual((root / "data" / "scan.db").read_bytes(), b"private")
            self.assertTrue((root / ".venv-install-failed" / "Scripts" / "python.exe").is_file())

    def test_restoration_does_not_overwrite_existing_quarantine(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            backup = root / ".venv-python315-backup"
            backup.mkdir()
            (backup / "marker").write_text("previous", encoding="utf-8")
            (root / ".venv").mkdir()
            (root / ".venv-install-failed").mkdir()
            with patch.object(setup, "ROOT", root), patch.object(setup, "VENV", root / ".venv"):
                self.assertTrue(setup.restore_venv_backup(backup))
            self.assertTrue((root / ".venv" / "marker").is_file())
            self.assertTrue((root / ".venv-install-failed-1").is_dir())
            self.assertTrue((root / ".venv-install-failed").is_dir())

    def test_no_old_venv_never_reports_rollback(self):
        self.assertFalse(setup.restore_venv_backup(None))

    def test_windows_batch_checks_private_env_copy_errors(self):
        text = (ROOT / "install-windows.bat").read_text(encoding="utf-8")
        self.assertIn('copy /Y ".env.example" ".env"', text)
        self.assertIn("Could not create private .env", text)
        self.assertIn("if errorlevel 1 (", text)

    def test_scanner_retry_bat_checks_self_check_exit_status(self):
        source = (ROOT / "install-scanners.bat").read_text(encoding="utf-8")
        self.assertIn('set "result=%errorlevel%"', source)
        self.assertIn('Component verification failed', source)
        self.assertIn('if "%result%"=="0" set "result=2"', source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
