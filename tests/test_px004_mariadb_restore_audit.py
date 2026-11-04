"""PX-004 read-only scratch recovery comparison contracts."""
from __future__ import annotations
from contextlib import redirect_stdout
from io import StringIO
import json
import os
import unittest
from unittest.mock import patch

from penx_app.application import mariadb_restore_audit as audit
from penx_app.application.backup_service import main as backup_cli


class FakeCursor:
    def __init__(self, changes=None):
        self.changes = changes or {}
        self.statements = []
        self.last = ""
        self.closed = False

    def execute(self, sql, params=None):
        self.statements.append((sql, params))
        self.last = sql

    def fetchall(self):
        if "information_schema.TABLES" in self.last:
            return self.changes.get("tables",
                                    [("history", "InnoDB"), ("summary", "InnoDB")])
        if "information_schema.COLUMNS" in self.last:
            return self.changes.get("columns", [
                ("history", 1, "sl_no", "int", "NO", None, "", None, None),
                ("summary", 1, "sl_no", "int", "NO", None, "", None, None),
            ])
        if "information_schema.STATISTICS" in self.last:
            return self.changes.get("indexes", [
                ("history", "PRIMARY", 0, 1, "sl_no", None, "BTREE"),
                ("summary", "uq_summary_sl_no", 0, 1, "sl_no", None, "BTREE"),
            ])
        raise AssertionError("Unexpected schema query")

    def fetchone(self):
        if "history" in self.last:
            return (self.changes.get("history_rows", 2),)
        if "summary" in self.last:
            return (self.changes.get("summary_rows", 2),)
        raise AssertionError("Unexpected count query")

    def close(self):
        self.closed = True


class FakeConnection:
    def __init__(self, changes=None):
        self.c = FakeCursor(changes)
        self.closed = False

    def cursor(self):
        return self.c

    def close(self):
        self.closed = True


class ScratchAuditTests(unittest.TestCase):
    def setUp(self):
        self.file = "fixture.sql"
        self.target = "penx_restore_" + "a" * 32
        self.plan = {
            "source_database": "penx_ci_test",
            "target_schema": self.target,
            "backup_sha256": "b" * 64,
            "plan_sha256": "c" * 64,
        }

    def compare(self, source=None, target=None):
        src = FakeConnection(source)
        dest = FakeConnection(target)
        with patch.object(audit, "plan_scratch_restore",
                          return_value=self.plan), \
             patch.object(audit, "_read_manifest",
                          return_value={"tables": ["history", "summary"], "source_database": "penx_ci_test"}), \
             patch.object(audit, "_read_only_mariadb_factory",
                          side_effect=[lambda: src, lambda: dest]) as factory:
            result = audit.audit_scratch_restore(
                self.file, target_schema=self.target,
                host="127.0.0.1", port=3306,
                source_user="src", source_password="secret1",
                target_user="dest", target_password="secret2")
        return result, src, dest, factory

    def test_parity_is_not_restore_authorization(self):
        result, src, dest, factory = self.compare()
        self.assertEqual(result["status"],
                         "observed-read-only-structural-parity")
        self.assertEqual(result["tables_compared"], 2)
        self.assertEqual(result["rows_counted_per_side"], 4)
        self.assertEqual(result["scratch_rows_counted"], 4)
        for flag in ("snapshot_contents_verified", "historical_backup_rows_verified",
                     "restore_available", "database_modified", "sql_executed"):
            self.assertFalse(result[flag])
        self.assertEqual(factory.call_count, 2)
        self.assertEqual(factory.call_args_list[0].args[2], "penx_ci_test")
        self.assertEqual(factory.call_args_list[1].args[2], self.target)
        for conn in (src, dest):
            self.assertTrue(conn.closed)
            self.assertTrue(conn.c.closed)
            self.assertTrue(all(sql.startswith("SELECT ")
                                for sql, _ in conn.c.statements))

    def test_mismatched_row_count_refused(self):
        with self.assertRaisesRegex(ValueError, "differ"):
            self.compare(target={"summary_rows": 3})

    def test_mismatched_schema_and_indexes_refused(self):
        with self.assertRaises(ValueError):
            self.compare(target={"indexes": [
                ("summary", "wrong_index", 0, 1, "sl_no", None, "BTREE")]})
        with self.assertRaises(ValueError):
            self.compare(target={"columns": [
                ("history", 1, "sl_no", "bigint", "NO", None, "", None, None),
                ("summary", 1, "sl_no", "int", "NO", None, "", None, None),
            ]})

    def test_missing_or_non_innodb_tables_refused(self):
        for tables in (
            [("history", "InnoDB")],
            [("history", "InnoDB"), ("summary", "MyISAM")],
            [("history", "InnoDB"), ("bad.name", "InnoDB")],
        ):
            with self.subTest(tables=tables), self.assertRaises(ValueError):
                self.compare(target={"tables": tables})

    def test_invalid_counts_and_incomplete_columns_refused(self):
        for values in (
            {"history_rows": -1},
            {"summary_rows": "2"},
            {"columns": [("history", 1, "sl_no", "int", "NO", None, "", None, None)]},
        ):
            with self.subTest(values=values), self.assertRaises(ValueError):
                self.compare(target=values)

    def test_invalid_backup_never_opens_database(self):
        with patch.object(audit, "_read_only_mariadb_factory",
                          side_effect=AssertionError("must not connect")), \
             self.assertRaises((OSError, ValueError)):
            audit.audit_scratch_restore(
                self.file, target_schema=self.target, host="127.0.0.1",
                port=3306, source_user="src", source_password="pw",
                target_user="dest", target_password="pw")

    def test_cli_secret_redaction(self):
        args = [
            "mariadb-restore-audit", "--file", self.file,
            "--target-schema", self.target, "--host", "127.0.0.1",
            "--source-user", "source_reader", "--target-user", "target_reader",
        ]
        with patch.dict(os.environ, {
            "PENX_VERIFY_MARIADB_PASSWORD": "secret1",
            "PENX_SCRATCH_AUDIT_PASSWORD": "secret2",
        }), patch.object(audit, "audit_scratch_restore",
                       side_effect=ValueError("secret1 SQL")), \
             redirect_stdout(StringIO()) as output:
            code = backup_cli(args)
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(output.getvalue())["status"], "unverified")
        self.assertNotIn("secret1", output.getvalue())

    def test_cli_output_never_claims_restore(self):
        args = [
            "mariadb-restore-audit", "--file", self.file,
            "--target-schema", self.target, "--host", "127.0.0.1",
            "--source-user", "source_reader", "--target-user", "target_reader",
        ]
        with patch.object(audit, "audit_scratch_restore", return_value={
            "status": "observed-read-only-structural-parity",
            "restore_available": False, "sql_executed": False,
        }), redirect_stdout(StringIO()) as output:
            code = backup_cli(args)
        self.assertEqual(code, 0)
        self.assertFalse(json.loads(output.getvalue())["restore_available"])


if __name__ == "__main__":
    unittest.main()
