"""PX-004 read-only SQL dump diagnostic checks on synthetic local fixtures."""
from __future__ import annotations

from contextlib import redirect_stdout
import hashlib
from io import StringIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from penx_app.application import mariadb_backup, mariadb_dump_diagnostics
from penx_app.application.backup_service import main as backup_cli


class MariaDBDumpInspectTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory(prefix="px004-dump-inspect-")
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name)
        self.path = self.root / (
            "penx-mariadb-20261104T180000Z-" + "a" * 32 + ".sql")
        self.tables = sorted(mariadb_backup.REQUIRED_TABLES)
        self.source = (
            "-- MariaDB dump synthetic fixture; NOT live data\n"
            + "".join(
                f"CREATE TABLE `{table}` (id int);\n"
                f"INSERT INTO `{table}` VALUES (1);\n"
                for table in self.tables
            )
            + "-- Dump completed on 2026-11-04\n"
        ).encode("utf-8")
        self.write_pair(self.source)

    def write_pair(self, payload):
        self.path.write_bytes(payload)
        manifest = {
            "schema": mariadb_backup.SCHEMA,
            "status": "complete-hash-verified",
            "file": self.path.name,
            "source_database": "penx_ci_test",
            "tables": self.tables,
            "created_at": "2026-11-04T18:00:00Z",
            "size_bytes": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "capture_method": "mariadb-dump-single-transaction-innodb",
        }
        self.path.with_suffix(".json").write_text(
            json.dumps(manifest), encoding="utf-8")

    def inspect(self, payload=None):
        if payload is not None:
            self.write_pair(payload)
        return mariadb_dump_diagnostics.inspect_logical_dump(self.path)

    def test_synthetic_normal_format_still_never_authorizes_restore(self):
        info = self.inspect()
        self.assertEqual(info["schema"], "penx-mariadb-dump-diagnostic-v1")
        self.assertEqual(info["status"], "manual-review-required")
        self.assertEqual(info["risk_flags"], [])
        self.assertEqual(info["manifest_table_count"], len(self.tables))
        self.assertEqual(info["observed_create_table_count"], len(self.tables))
        self.assertEqual(info["inspected_bytes"], len(self.source))
        self.assertEqual(info["backup_sha256"], hashlib.sha256(self.source).hexdigest())
        for key in ("restore_available", "sql_executed",
                    "sql_semantics_verified", "historical_backup_rows_verified"):
            self.assertFalse(info[key])
        self.assertNotIn("INSERT INTO", json.dumps(info))
        self.assertNotIn("penx_ci_test", json.dumps(info))

    def test_executable_comments_and_client_directives_flagged(self):
        cases = [
            (b"/*!50000 DROP DATABASE penx_ci_test */;\n", "executable-comment"),
            (b"/*M!100100 SET NAMES latin1 */;\n", "executable-comment"),
            (b"/* opaque */\n", "block-comment"),
            (b"DELIMITER $$\n", "client-delimiter-or-source"),
            (b"SOURCE /tmp/hidden.sql\n", "client-delimiter-or-source"),
            (b"LOAD DATA INFILE 'x' INTO TABLE history;\n", "external-data-access"),
            (b"SELECT 1 INTO OUTFILE '/tmp/leak';\n", "external-data-access"),
            (b"DROP DATABASE penx_ci_test;\n", "schema-context-change"),
            (b"USE other_schema;\n", "schema-context-change"),
            (b"GRANT ALL ON *.* TO 'x';\n", "privilege-or-program-execution"),
            (b"SET NAMES latin1;\n", "session-mode-or-charset-change"),
            (b"DROP TABLE history;\n", "destructive-or-unexpected-write"),
            (b"UPDATE history SET id=2;\n", "destructive-or-unexpected-write"),
            (b"INSERT INTO `other` VALUES (1);\n", "table-not-in-manifest"),
            (b"SELECT * FROM `other_schema`.`history`;\n",
             "cross-schema-identifier"),
        ]
        for payload, flag in cases:
            with self.subTest(flag=flag, payload=payload):
                report = self.inspect(self.source + payload)
                self.assertIn(flag, report["risk_flags"])
                self.assertFalse(report["restore_available"])

    def test_missing_duplicate_unknown_and_reordered_schema_are_flagged(self):
        sql = self.source.decode("utf-8")
        missing = sql.replace("CREATE TABLE `history` (id int);\n", "", 1)
        self.assertIn("missing-table-creation",
                      self.inspect(missing.encode())["risk_flags"])
        self.assertIn("insert-before-create",
                      self.inspect(missing.encode())["risk_flags"])
        duplicate = sql.replace(
            "CREATE TABLE `history` (id int);\n",
            "CREATE TABLE `history` (id int);\n"
            "CREATE TABLE `history` (id int);\n", 1)
        self.assertIn("duplicate-create-table",
                      self.inspect(duplicate.encode())["risk_flags"])
        unexpected = sql + "CREATE TABLE `unlisted` (id int);\n"
        self.assertIn("table-not-in-manifest",
                      self.inspect(unexpected.encode())["risk_flags"])
        reversed_order = sql.replace(
            "CREATE TABLE `history` (id int);\n"
            "INSERT INTO `history` VALUES (1);\n",
            "INSERT INTO `history` VALUES (1);\n"
            "CREATE TABLE `history` (id int);\n", 1)
        self.assertIn("insert-before-create",
                      self.inspect(reversed_order.encode())["risk_flags"])

    def test_absent_footer_is_uncertainty_not_proof_of_truncation(self):
        sample = self.source.replace(
            b"-- Dump completed on 2026-11-04\n", b"")
        report = self.inspect(sample)
        self.assertIn("completion-marker-not-observed", report["risk_flags"])
        self.assertEqual(report["status"], "manual-review-required")

    def test_invalid_utf8_nul_and_resource_budgets_fail_closed(self):
        for suffix in (b"\xff", b"\x00", b"\x01"):
            with self.subTest(suffix=suffix), self.assertRaises(ValueError):
                self.inspect(self.source + suffix)
        with patch.object(mariadb_dump_diagnostics, "MAX_INSPECTION_BYTES", 32):
            with self.assertRaisesRegex(ValueError, "budget"):
                self.inspect(self.source)
        with patch.object(mariadb_dump_diagnostics, "MAX_LINE_CHARS", 16):
            with self.assertRaisesRegex(ValueError, "line budget"):
                self.inspect(self.source)
        with patch.object(mariadb_dump_diagnostics, "MAX_LINES", 4):
            with self.assertRaisesRegex(ValueError, "line budget"):
                self.inspect(self.source)

    def test_hash_and_manifest_tampering_fail_before_diagnostics(self):
        self.path.write_bytes(self.source + b"-- modified\n")
        with self.assertRaises(ValueError):
            mariadb_dump_diagnostics.inspect_logical_dump(self.path)
        self.write_pair(self.source)
        self.path.with_suffix(".json").unlink()
        with self.assertRaises(ValueError):
            mariadb_dump_diagnostics.inspect_logical_dump(self.path)

    def test_no_db_network_or_process_execution_and_no_sql_echo(self):
        with (patch("subprocess.run", side_effect=AssertionError("ran process")),
              patch("socket.create_connection",
                    side_effect=AssertionError("opened socket")),
              redirect_stdout(StringIO()) as output):
            self.assertEqual(backup_cli(
                ["mariadb-dump-inspect", "--file", str(self.path)]), 0)
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["status"], "manual-review-required")
        self.assertNotIn("CREATE TABLE", output.getvalue())
        self.assertNotIn("penx_ci_test", output.getvalue())
        self.assertFalse(payload["restore_available"])

    def test_cli_untrusted_input_is_generic_and_nonzero(self):
        self.path.write_bytes(b"malicious")
        with redirect_stdout(StringIO()) as output:
            rc = backup_cli(["mariadb-dump-inspect", "--file", str(self.path)])
        self.assertEqual(rc, 2)
        report = json.loads(output.getvalue())
        self.assertEqual(report["status"], "unverified")
        self.assertFalse(report["restore_available"])
        self.assertNotIn("malicious", output.getvalue())


if __name__ == "__main__":
    unittest.main()
