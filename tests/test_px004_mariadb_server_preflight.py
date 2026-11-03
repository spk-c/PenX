"""PX-004 live read-only scratch schema preflight; no DDL or import."""
from __future__ import annotations

from contextlib import redirect_stdout
from io import StringIO
import json
import os
import unittest
from unittest.mock import Mock, patch

from penx_app.application import mariadb_restore_plan as plan
from penx_app.application.backup_service import main as backup_cli


class ScratchSchemaPreflightTests(unittest.TestCase):
    def setUp(self):
        self.backup = "synthetic-fixture.sql"
        self.target = "penx_restore_" + "a" * 32
        self.info = {
            "status": "read-only-plan",
            "source_database": "penx_ci_test",
            "target_schema": self.target,
            "plan_sha256": "f" * 64,
            "restore_available": False,
            "maintenance_and_rollback_not_verified": True,
            "sql_executed": False,
        }
        self.account_grants = [
            ("GRANT USAGE ON *.* TO 'penx_ci'@'%'",),
            ("GRANT SHOW DATABASES ON *.* TO 'penx_ci'@'%'",),
            ("GRANT SELECT ON penx_ci_test.* TO 'penx_ci'@'%'",),
        ]

    def run_check(self, *, grants=None, schemas=None, target=None):
        factory = Mock()
        connection = factory.return_value.return_value
        cursor = connection.cursor.return_value
        cursor.fetchall.side_effect = [
            self.account_grants if grants is None else grants,
            [] if schemas is None else schemas,
        ]
        with patch.object(plan, "plan_scratch_restore", return_value=self.info), \
             patch.object(plan, "_read_only_mariadb_factory",
                          return_value=factory.return_value):
            result = plan.preflight_scratch_target(
                self.backup, target_schema=target or self.target,
                host="127.0.0.1", port=3306, database="penx_ci_test",
                user="penx_ci", password="test-only")
        return result, connection, cursor

    def test_positive_snapshot_never_grants_restore_permission(self):
        result, conn, cursor = self.run_check()
        self.assertEqual(result["status"], "read-only-server-preflight")
        self.assertEqual(result["target_existence"], "absent-at-check-time-only")
        self.assertTrue(result["server_snapshot_checked"])
        self.assertFalse(result["restore_available"])
        self.assertFalse(result["target_reserved"])
        self.assertFalse(result["sql_executed"])
        self.assertTrue(result["maintenance_and_rollback_not_verified"])
        self.assertEqual(cursor.execute.call_count, 2)
        self.assertEqual(cursor.execute.call_args.args[1], (self.target,))
        self.assertIn("information_schema.SCHEMATA",
                      cursor.execute.call_args.args[0])
        self.assertIn("LOWER(SCHEMA_NAME)", cursor.execute.call_args.args[0])
        cursor.close.assert_called_once()
        conn.close.assert_called_once()

    def test_existing_case_variant_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "already exists"):
            self.run_check(schemas=[(self.target.upper(),)])

    def test_missing_global_visibility_is_rejected_even_if_target_hidden(self):
        for grants in (
            [("GRANT SELECT ON penx_ci_test.* TO 'penx_ci'@'%'",)],
            [("GRANT USAGE ON *.* TO 'penx_ci'@'%'",)],
            [("GRANT ALL PRIVILEGES ON *.* TO 'root'@'%'",)],
            [("GRANT SHOW DATABASES ON penx_ci_test.* TO 'x'@'%'",)],
            [("GRANT introspection_role TO 'x'@'%'",)],
            [],
            [("GRANT SHOW DATABASES ON *.* TO 'x'@'%'", "extra")],
        ):
            with self.subTest(grants=grants), \
                 self.assertRaisesRegex(ValueError, "visibility"):
                self.run_check(grants=grants)

    def test_global_grant_in_multi_privilege_grant_recognized(self):
        granted = [
            ("GRANT SELECT, SHOW DATABASES ON *.* TO 'reader'@'%'",)
        ]
        result, _, _ = self.run_check(grants=granted)
        self.assertEqual(result["schema_visibility"],
                         "explicit-global-show-databases")

    def test_plan_rejection_prevents_connection_attempt(self):
        with patch.object(
            plan, "plan_scratch_restore",
            side_effect=ValueError("backup digest mismatch"),
        ), patch.object(
            plan, "_read_only_mariadb_factory",
            side_effect=AssertionError("no DB before backup validation"),
        ), self.assertRaisesRegex(ValueError, "digest"):
            plan.preflight_scratch_target(
                self.backup, target_schema=self.target,
                host="127.0.0.1", port=3306, database="penx_ci_test",
                user="penx_ci", password="secret")

    def test_mismatched_source_database_rejected_before_connection(self):
        with patch.object(plan, "plan_scratch_restore",
                          return_value=self.info), \
             patch.object(
                 plan, "_read_only_mariadb_factory",
                 side_effect=AssertionError("no DB should be opened"),
             ), self.assertRaisesRegex(ValueError, "differs"):
            plan.preflight_scratch_target(
                self.backup, target_schema=self.target,
                host="127.0.0.1", port=3306, database="other_schema",
                user="penx_ci", password="secret")

    def test_invalid_remote_hostname_rejected_before_query(self):
        with patch.object(plan, "plan_scratch_restore",
                          return_value=self.info), \
             self.assertRaises(ValueError):
            plan.preflight_scratch_target(
                self.backup, target_schema=self.target,
                host="evil.example.com", port=3306, database="penx_ci_test",
                user="penx_ci", password="secret")

    def test_query_error_closes_read_only_connection(self):
        factory = Mock()
        conn = factory.return_value.return_value
        cursor = conn.cursor.return_value
        cursor.execute.side_effect = RuntimeError("mock SQL error")
        with patch.object(plan, "plan_scratch_restore",
                          return_value=self.info), \
             patch.object(plan, "_read_only_mariadb_factory",
                          return_value=factory.return_value), \
             self.assertRaises(RuntimeError):
            plan.preflight_scratch_target(
                self.backup, target_schema=self.target,
                host="127.0.0.1", port=3306, database="penx_ci_test",
                user="penx_ci", password="secret")
        cursor.close.assert_called_once()
        conn.close.assert_called_once()

    def test_cli_requires_separate_password_and_masks_database_errors(self):
        args = [
            "mariadb-restore-preflight", "--file", self.backup,
            "--target-schema", self.target, "--host", "127.0.0.1",
            "--database", "penx_ci_test", "--user", "penx_reader",
        ]
        with patch.dict(os.environ, {"PENX_VERIFY_MARIADB_PASSWORD": ""}), \
             redirect_stdout(StringIO()) as output:
            code = backup_cli(args)
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output.getvalue())["status"], "unverified")
        with patch.dict(os.environ,
                        {"PENX_VERIFY_MARIADB_PASSWORD": "top-secret"}), \
             patch.object(plan, "preflight_scratch_target",
                          side_effect=RuntimeError("top-secret SQL state")), \
             redirect_stdout(StringIO()) as output:
            code = backup_cli(args)
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output.getvalue())["status"], "unverified")
        self.assertNotIn("top-secret", output.getvalue())

    def test_cli_report_success_is_explicitly_non_executable(self):
        args = [
            "mariadb-restore-preflight", "--file", self.backup,
            "--target-schema", self.target, "--host", "127.0.0.1",
            "--database", "penx_ci_test", "--user", "penx_reader",
        ]
        with patch.dict(os.environ,
                        {"PENX_VERIFY_MARIADB_PASSWORD": "mock-secret"}), \
             patch.object(plan, "preflight_scratch_target",
                          return_value={**self.info,
                                        "status": "read-only-server-preflight",
                                        "target_existence":
                                        "absent-at-check-time-only"}), \
             redirect_stdout(StringIO()) as output:
            code = backup_cli(args)
        self.assertEqual(code, 0)
        summary = json.loads(output.getvalue())
        self.assertEqual(summary["status"], "read-only-server-preflight")
        self.assertFalse(summary["restore_available"])
        self.assertNotIn("mock-secret", output.getvalue())


if __name__ == "__main__":
    unittest.main()
