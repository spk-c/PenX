"""PX-004 offline tests: tamper-proof MariaDB file pairs and no live restore."""
from __future__ import annotations

from contextlib import redirect_stdout
from io import StringIO
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from penx_app.application import mariadb_backup as mb
from penx_app.application.backup_service import main as backup_cli


class MariaDBBackupContracts(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.tables = sorted(mb.REQUIRED_TABLES | {"learned_rules"})
        self.fake_dump = b"-- local fixture\\nCREATE TABLE history (id INT);\\n"

    def make_backup(self, data=None):
        payload = self.fake_dump if data is None else data

        def dump(args, *, stdout, stderr, env, timeout, check):
            self.assertIs(stderr, mb.subprocess.DEVNULL)
            self.assertFalse(check)
            self.assertEqual(timeout, 180)
            self.assertNotIn("unit-secret", str(args))
            self.assertEqual(args[0:2], ["mariadb-dump", "--no-defaults"])
            self.assertIn("--single-transaction", args)
            self.assertIn("--skip-add-drop-table", args)
            self.assertNotIn("--databases", args)
            self.assertEqual(env["MYSQL_PWD"], "unit-secret")
            self.assertNotIn("PENX_MARIADB_BACKUP_PASSWORD", env)
            stdout.write(payload)
            return Mock(returncode=0)

        with patch.object(mb, "_read_only_mariadb_factory"), \
             patch.object(mb, "_source_tables", return_value=self.tables), \
             patch.object(mb.subprocess, "run", side_effect=dump):
            return mb.create_logical_backup(
                host="127.0.0.1", port=3306, database="penx_test",
                user="readonly", password="unit-secret", directory=self.root)

    def paths(self):
        sql = next(self.root.glob("penx-mariadb-*.sql"))
        return sql, sql.with_suffix(".json")

    def test_create_verify_preview(self):
        report = self.make_backup()
        sql, meta = self.paths()
        self.assertEqual(report["status"], "verified-file-integrity-only")
        self.assertEqual(report["size_bytes"], len(self.fake_dump))
        self.assertEqual(report["sha256"], hashlib.sha256(self.fake_dump).hexdigest())
        self.assertEqual(sql.read_bytes(), self.fake_dump)
        self.assertEqual(mb.verify_logical_backup(sql), report)
        self.assertFalse(mb.preview_logical_backup(meta)["restore_available"])
        manifest = json.loads(meta.read_text())
        self.assertEqual(manifest["source_database"], "penx_test")
        self.assertEqual(manifest["tables"], self.tables)

    def test_tampering_file_and_metadata_fail_closed(self):
        self.make_backup()
        sql, meta = self.paths()
        sql.write_bytes(b"altered source bytes")
        with self.assertRaises(ValueError):
            mb.verify_logical_backup(sql)
        sql.write_bytes(self.fake_dump)
        manifest = json.loads(meta.read_text())
        manifest["file"] = "wrong.sql"
        meta.write_text(json.dumps(manifest), encoding="utf8")
        with self.assertRaises(ValueError):
            mb.verify_logical_backup(sql)

    def test_duplicate_json_fields_fail_closed(self):
        self.make_backup()
        sql, meta = self.paths()
        original = meta.read_text()
        meta.write_text(original.replace(
            '"status": ', '"status": "invalid", "status": ', 1), encoding="utf8")
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            mb.verify_logical_backup(sql)

    def test_missing_manifest_never_verifies(self):
        self.make_backup()
        sql, meta = self.paths()
        meta.unlink()
        with self.assertRaises(ValueError):
            mb.verify_logical_backup(sql)

    def test_symlink_to_dump_is_rejected(self):
        self.make_backup()
        sql, _ = self.paths()
        actual = self.root / "actual.sql"
        sql.rename(actual)
        try:
            sql.symlink_to(actual)
        except (OSError, NotImplementedError):
            return
        with self.assertRaises(ValueError):
            mb.verify_logical_backup(sql)

    def test_client_failure_does_not_publish(self):
        with patch.object(mb, "_read_only_mariadb_factory"), \
             patch.object(mb, "_source_tables", return_value=self.tables), \
             patch.object(mb.subprocess, "run",
                          return_value=Mock(returncode=1)):
            with self.assertRaises(ValueError):
                mb.create_logical_backup(
                    host="127.0.0.1", port=3306, database="penx_test",
                    user="reader", password="unit-secret", directory=self.root)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_empty_and_over_limit_source_never_published(self):
        for payload in (b"", b"0123456789abcdef"):
            with self.subTest(length=len(payload)), \
                 patch.object(mb, "MAX_DUMP_BYTES", 8 if payload else 512):
                with self.assertRaises(ValueError):
                    self.make_backup(data=payload)
                self.assertFalse(list(self.root.glob("*.sql")))

    def test_innodb_table_preflight_blocks_mixed_or_missing_schema(self):
        good = [(name, "InnoDB") for name in self.tables]
        for rows in (good[:-2], [(name, "MyISAM" if i == 0 else "InnoDB")
                                 for i, (name, _) in enumerate(good)]):
            with patch.object(mb, "_read_only_mariadb_factory") as factory:
                connection = Mock()
                connection.cursor.return_value.fetchall.return_value = rows
                factory.return_value.return_value = connection
                with self.assertRaises(ValueError):
                    mb._source_tables("127.0.0.1", 3306, "penx_test",
                                      "reader", "pw")

    def test_remote_backup_target_fails_before_any_output_or_dump(self):
        with patch.object(mb, "_source_tables",
                          side_effect=AssertionError("must not access DB")), \
             patch.object(mb.subprocess, "run",
                          side_effect=AssertionError("must not run dump")):
            with self.assertRaises(ValueError):
                mb.create_logical_backup(
                    host="example.com", port=3306, database="penx_test",
                    user="reader", password="unit-secret",
                    directory=self.root)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_invalid_dump_executable_or_missing_output_directory(self):
        with self.assertRaises(ValueError):
            mb.create_logical_backup(
                host="127.0.0.1", port=3306, database="penx_test",
                user="reader", password="pw", directory=self.root,
                executable="powershell.exe")
        with self.assertRaises(ValueError):
            mb.create_logical_backup(
                host="127.0.0.1", port=3306, database="penx_test",
                user="reader", password="pw", directory=self.root / "missing")

    def test_cli_explicit_secret_and_failure_redaction(self):
        args = ["mariadb-create", "--host", "127.0.0.1", "--database",
                "penx_test", "--user", "reader", "--output-dir", str(self.root)]
        with patch.dict(os.environ, {"PENX_MARIADB_BACKUP_PASSWORD": ""}), \
             redirect_stdout(StringIO()) as output:
            self.assertEqual(backup_cli(args), 2)
        self.assertEqual(json.loads(output.getvalue())["status"], "unverified")
        with patch.dict(os.environ, {"PENX_MARIADB_BACKUP_PASSWORD": "secret"}), \
             patch.object(mb, "create_logical_backup",
                          side_effect=ValueError("secret database")), \
             redirect_stdout(StringIO()) as output:
            self.assertEqual(backup_cli(args), 2)
        self.assertNotIn("secret", output.getvalue())

    def test_verify_preview_are_offline(self):
        self.make_backup()
        sql, _ = self.paths()
        with patch.object(mb, "_read_only_mariadb_factory",
                          side_effect=AssertionError("unexpected DB")), \
             redirect_stdout(StringIO()) as output:
            self.assertEqual(backup_cli(["mariadb-verify",
                                         "--file", str(sql)]), 0)
            self.assertEqual(backup_cli(["mariadb-preview",
                                         "--file", str(sql)]), 0)
        lines = output.getvalue().splitlines()
        self.assertEqual(len(lines), 2)
        self.assertFalse(json.loads(lines[1])["restore_available"])

    def test_no_live_mariadb_restore_command(self):
        with redirect_stdout(StringIO()):
            self.assertEqual(backup_cli(["mariadb-restore"]), 2)


if __name__ == "__main__":
    unittest.main()

