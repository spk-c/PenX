"""PX-004: headless `penx backup` CLI contract (exit codes, guards, output)."""
from __future__ import annotations

from contextlib import closing, redirect_stderr, redirect_stdout
import io
import sqlite3
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from penx_app.application import backup_service
from penx_app.storage import backup as backup_store
from penx_app.storage.schema_migrations import SCHEMA, SCHEMA_VERSION, initialize_sqlite

import penx_app.config as config


def _run(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = backup_service.main(argv)
    return code, out.getvalue(), err.getvalue()


class BackupCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="penx-backup-cli-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db = self.root / "penx.db"
        self.dest = self.root / "backups"
        self.settings = types.SimpleNamespace(
            DB_ENGINE="sqlite", DB_PATH=str(self.db)
        )
        self._settings_patch = patch.object(config, "_settings", self.settings)
        self._settings_patch.start()
        self.addCleanup(self._settings_patch.stop)
        self._dir_patch = patch.object(
            backup_service, "default_backup_dir", lambda: self.dest
        )
        self._dir_patch.start()
        self.addCleanup(self._dir_patch.stop)

    def make_current(self, path: Path) -> None:
        conn = sqlite3.connect(str(path))
        initialize_sqlite(conn)
        conn.execute(
            "INSERT INTO history (target, scan_date) "
            "VALUES ('fixture.example.test', '2025-01-01')"
        )
        conn.commit()
        conn.close()

    def make_legacy_v2_duplicate(self, path: Path) -> None:
        conn = sqlite3.connect(str(path))
        conn.executescript(SCHEMA + "\nPRAGMA user_version=2;")
        conn.execute(
            "INSERT INTO history (sl_no, target, scan_date) "
            "VALUES (7, 'fixture.example.test', '2025-01-01')"
        )
        conn.execute(
            "INSERT INTO summary (id, sl_no, raw_scan) VALUES (9, 7, 'raw a')"
        )
        conn.execute(
            "INSERT INTO summary (id, sl_no, raw_scan) VALUES (10, 7, 'raw b')"
        )
        conn.commit()
        conn.close()

    def test_create_defaults_to_configured_db_and_backup_dir(self):
        self.make_current(self.db)
        code, out, err = _run(["create"])
        self.assertEqual(code, 0, err)
        self.assertIn("[OK] Backup created and verified.", out)
        backups = list(self.dest.glob("penx-backup-*.sqlite"))
        self.assertEqual(len(backups), 1)

    def test_create_mariadb_engine_requires_explicit_db(self):
        self.settings.DB_ENGINE = "mariadb"
        code, out, err = _run(["create"])
        self.assertEqual(code, 2)
        self.assertIn("mariadb", err)

    def test_verify_valid_and_tampered(self):
        self.make_current(self.db)
        _, out, _ = _run(["create"])
        backup = Path(out.split("Backup: ")[1].splitlines()[0])
        code, out, _ = _run(["verify", "--file", str(backup)])
        self.assertEqual(code, 0, out)
        self.assertIn("[OK] Backup verified.", out)
        data = bytearray(backup.read_bytes())
        data[-1] ^= 0xFF
        backup.write_bytes(bytes(data))
        code, out, _ = _run(["verify", "--file", str(backup)])
        self.assertEqual(code, 1)
        self.assertIn("sha256 mismatch", out)

    def test_preview_reports_rows_and_migration(self):
        self.make_current(self.db)
        _, out, _ = _run(["create"])
        backup = Path(out.split("Backup: ")[1].splitlines()[0])
        code, out, _ = _run(["preview", "--file", str(backup)])
        self.assertEqual(code, 0, out)
        self.assertIn("history: 1", out)
        self.assertIn("Migration: not required", out)

    def test_preview_legacy_migration_dry_run(self):
        source = self.root / "legacy.db"
        self.make_legacy_v2_duplicate(source)
        code, out, err = _run(["create", "--db", str(source),
                              "--output-dir", str(self.dest)])
        self.assertEqual(code, 0, err)
        backup = Path(out.split("Backup: ")[1].splitlines()[0])
        code, out, _ = _run(["preview", "--file", str(backup)])
        self.assertEqual(code, 1)
        self.assertIn("dry run FAILED", out)
        self.assertIn("migration v3 blocked", out)

    def test_restore_requires_confirm_flag(self):
        self.make_current(self.db)
        _, out, _ = _run(["create"])
        backup = Path(out.split("Backup: ")[1].splitlines()[0])
        code, out, err = _run(["restore", "--file", str(backup)])
        self.assertEqual(code, 2)
        self.assertIn("--confirm", err)

    def test_restore_with_confirm_replaces_live(self):
        self.make_current(self.db)
        _, out, _ = _run(["create"])
        backup = Path(out.split("Backup: ")[1].splitlines()[0])
        with closing(sqlite3.connect(str(self.db))) as conn:
            conn.execute(
                "INSERT INTO history (target, scan_date) "
                "VALUES ('after.example.test', '2025-02-02')"
            )
            conn.commit()
        code, out, err = _run(
            ["restore", "--file", str(backup), "--confirm"]
        )
        self.assertEqual(code, 0, err)
        self.assertIn("[OK] Restored", out)
        self.assertIn("Pre-restore backup:", out)
        with closing(sqlite3.connect(str(self.db))) as conn:
            targets = {
                row[0] for row in conn.execute("SELECT target FROM history")
            }
        self.assertEqual(targets, {"fixture.example.test"})

    def test_restore_failed_migration_keeps_exit_2_and_live(self):
        self.make_current(self.db)
        source = self.root / "legacy.db"
        self.make_legacy_v2_duplicate(source)
        code, out, _ = _run(
            ["create", "--db", str(source), "--output-dir", str(self.dest)]
        )
        self.assertEqual(code, 0)
        backup = Path(out.split("Backup: ")[1].splitlines()[0])
        before = self.db.read_bytes()
        code, out, err = _run(["restore", "--file", str(backup), "--confirm"])
        self.assertEqual(code, 2, err)
        self.assertIn("migration v3 blocked", err)
        self.assertEqual(self.db.read_bytes(), before)

    def test_usage_errors_return_2(self):
        for argv in ([], ["bogus"], ["verify"], ["restore"]):
            with self.subTest(argv=argv):
                code, _, _ = _run(argv)
                self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
