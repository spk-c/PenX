"""Offline PX-004 scratch restore-plan safety contracts."""
from __future__ import annotations

from contextlib import redirect_stdout
from io import StringIO
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from penx_app.application import mariadb_backup, mariadb_restore_plan
from penx_app.application.backup_service import main as backup_cli


class MariaDBRestorePlanTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="penx-restore-plan-")
        self.addCleanup(tmp.cleanup)
        self.folder = Path(tmp.name)
        self.backup = self.folder / (
            "penx-mariadb-20261103T220000Z-" + "a" * 32 + ".sql")
        self.fixture = b"CREATE TABLE history (id INT);\n-- synthetic data\n"
        self.backup.write_bytes(self.fixture)
        self.write_manifest()
        self.target = "penx_restore_" + "b" * 32

    def write_manifest(self):
        data = self.backup.read_bytes()
        manifest = {
            "schema": mariadb_backup.SCHEMA,
            "status": "complete-hash-verified",
            "file": self.backup.name,
            "source_database": "penx_ci_test",
            "tables": sorted(mariadb_backup.REQUIRED_TABLES),
            "created_at": "2026-11-03T22:00:00Z",
            "size_bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "capture_method": "mariadb-dump-single-transaction-innodb",
        }
        self.backup.with_suffix(".json").write_text(
            json.dumps(manifest), encoding="utf-8")

    def plan(self, target=None):
        return mariadb_restore_plan.plan_scratch_restore(
            self.backup,
            target_schema=self.target if target is None else target,
        )

    def test_immutable_identity_and_explicit_nonexecution(self):
        result = self.plan()
        self.assertEqual(result["status"], "read-only-plan")
        self.assertEqual(result["target_schema"], self.target)
        self.assertEqual(result["target_existence"], "not-checked")
        self.assertTrue(result["target_must_be_new_and_empty"])
        self.assertTrue(result["production_pre_restore_backup_required"])
        self.assertTrue(result["maintenance_and_rollback_not_verified"])
        self.assertFalse(result["restore_available"])
        self.assertFalse(result["sql_executed"])
        self.assertFalse(result["sql_semantics_verified"])
        self.assertEqual(result["plan_sha256"], self.plan()["plan_sha256"])
        self.assertNotIn("CREATE TABLE", json.dumps(result))

    def test_never_contacts_database_or_runs_subprocess(self):
        with patch.object(
            mariadb_backup, "_read_only_mariadb_factory",
            side_effect=AssertionError("unexpected database connection"),
        ), patch(
            "subprocess.run",
            side_effect=AssertionError("unexpected subprocess"),
        ):
            self.assertTrue(self.plan()["plan_sha256"])

    def test_rejects_bad_destination_names(self):
        cases = [
            "", "penx_ci_test", "mysql", "production",
            "penx_restore_", "penx_restore_" + "a" * 31,
            "penx_restore_" + "A" * 32,
            "penx_restore_" + "a" * 33,
            "penx_restore_" + "a" * 32 + ";DROP DATABASE penx",
            "../penx_restore_" + "a" * 32,
            " penx_restore_" + "a" * 32,
        ]
        for value in cases:
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.plan(value)
        with self.assertRaises(ValueError):
            mariadb_restore_plan.plan_scratch_restore(
                self.backup, target_schema=None)

    def test_hash_corruption_and_missing_manifest(self):
        self.backup.write_bytes(self.fixture + b"-- tampered\n")
        with self.assertRaises(ValueError):
            self.plan()
        self.backup.write_bytes(self.fixture)
        self.backup.with_suffix(".json").unlink()
        with self.assertRaises(ValueError):
            self.plan()

    def test_target_binding_changes_plan_id(self):
        first = self.plan()
        second = self.plan("penx_restore_" + "c" * 32)
        self.assertNotEqual(first["plan_sha256"], second["plan_sha256"])
        self.assertEqual(first["backup_sha256"], second["backup_sha256"])

    def test_new_hash_after_manifest_and_file_change(self):
        first = self.plan()
        self.backup.write_bytes(self.fixture + b"-- next version\n")
        self.write_manifest()
        second = self.plan()
        self.assertNotEqual(first["plan_sha256"], second["plan_sha256"])

    def test_cli_is_offline_and_silent_about_source_contents(self):
        with redirect_stdout(StringIO()) as buffer:
            rc = backup_cli([
                "mariadb-restore-plan", "--file", str(self.backup),
                "--target-schema", self.target,
            ])
        self.assertEqual(rc, 0)
        data = json.loads(buffer.getvalue())
        self.assertFalse(data["restore_available"])
        self.assertEqual(data["target_schema"], self.target)
        self.assertNotIn("CREATE TABLE", buffer.getvalue())

    def test_cli_malformed_target_or_file_fail_closed(self):
        for arg in (
            ["--file", str(self.backup), "--target-schema", "production"],
            ["--file", "missing.sql", "--target-schema", self.target],
        ):
            with self.subTest(arg=arg), redirect_stdout(StringIO()) as out:
                rc = backup_cli(["mariadb-restore-plan", *arg])
                self.assertEqual(rc, 2)
                self.assertEqual(
                    json.loads(out.getvalue())["status"], "unverified")

    def test_symlinked_backup_rejected(self):
        real = self.folder / "real.sql"
        self.backup.rename(real)
        try:
            self.backup.symlink_to(real)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks not available")
        with self.assertRaises(ValueError):
            self.plan()


if __name__ == "__main__":
    unittest.main()
