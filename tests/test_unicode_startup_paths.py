"""Headless source/installed startup from paths with spaces and Unicode.

These checks do not install Npcap or execute scanners. Manual UAC and actual
third-party installer checks remain separate Windows release gates.
"""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class UnicodeStartupContracts(unittest.TestCase):
    def test_checkout_launcher_outside_checkout_with_unicode_working_directory(self):
        with tempfile.TemporaryDirectory(prefix="penx-ü-space-") as root:
            target = Path(root) / "Verzeichnis mit Leerzeichen_日本語"
            target.mkdir()
            env = {**os.environ, "PENX_DB_ENGINE": "intentionally-invalid",
                   "PENX_LLM_URL": "intentionally-invalid"}
            completed = subprocess.run(
                [sys.executable, str(ROOT / "penx.py"), "--version"],
                cwd=target, env=env, stdin=subprocess.DEVNULL,
                text=True, encoding="utf-8", errors="replace",
                capture_output=True, timeout=30, check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("PenX", completed.stdout)
            self.assertEqual(list(target.iterdir()), [])

    def test_module_entrypoints_from_unicode_working_directory(self):
        with tempfile.TemporaryDirectory(prefix="penx-ü-space-") as root:
            target = Path(root) / "Schreibgeschützt simuliert_日本語"
            target.mkdir()
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src"),
                   "PENX_DB_ENGINE": "intentionally-invalid",
                   "PENX_LLM_URL": "intentionally-invalid"}
            for module in ("penx", "penx_app"):
                with self.subTest(module=module):
                    completed = subprocess.run(
                        [sys.executable, "-m", module, "--version"],
                        cwd=target, env=env, stdin=subprocess.DEVNULL,
                        text=True, encoding="utf-8", errors="replace",
                        capture_output=True, timeout=30, check=False,
                    )
                    self.assertEqual(completed.returncode, 0, completed.stderr)
                    self.assertIn("PenX", completed.stdout)
            self.assertEqual(list(target.iterdir()), [])

    def test_headless_status_never_installs_or_opens_database(self):
        with tempfile.TemporaryDirectory(prefix="penx-ü-space-") as root:
            target = Path(root) / "Status mit Leerzeichen"
            target.mkdir()
            env = {**os.environ, "PYTHONPATH": str(ROOT / "src"),
                   "PENX_DB_ENGINE": "intentionally-invalid"}
            completed = subprocess.run(
                [sys.executable, "-m", "penx_app", "--setup-status"],
                cwd=target, env=env, stdin=subprocess.DEVNULL,
                text=True, encoding="utf-8", errors="replace",
                capture_output=True, timeout=30, check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("presence checks", completed.stdout)
            self.assertFalse(list(target.glob("*.db")))
            self.assertFalse(list(target.glob("*.env")))


if __name__ == "__main__":
    unittest.main()
