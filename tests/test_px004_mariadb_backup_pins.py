"""PX-004 synthetic offline external pin verification and tamper regressions."""
from __future__ import annotations

from contextlib import redirect_stdout
from io import StringIO
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from penx_app.application import mariadb_backup as mb
from penx_app.application import mariadb_backup_pins as pins
from penx_app.application.backup_service import main as backup_cli


class MariaDBExternalPinContracts(unittest.TestCase):
    def setUp(self):
        root = tempfile.TemporaryDirectory(prefix="px004-external-pins-")
        self.addCleanup(root.cleanup)
        self.root = Path(root.name)
        name = "penx-mariadb-20261104T200000Z-" + ("b" * 32)
        self.sql = self.root / (name + ".sql")
        self.meta = self.root / (name + ".json")
        self.original = (
            b"-- Synthetic MariaDB dump; not actual operator data\n"
            b"CREATE TABLE `history` (id INT);\n"
            b"INSERT INTO `history` VALUES (1);\n"
            b"-- Dump completed on 2026-11-04\n"
        )
        self.write_pair(self.original)
        self.original_sql_sha = self.sha(self.sql)
        self.original_meta_sha = self.sha(self.meta)

    @staticmethod
    def sha(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def write_pair(self, payload: bytes, **changes):
        self.sql.write_bytes(payload)
        manifest = {
            "schema": mb.SCHEMA,
            "status": "complete-hash-verified",
            "file": self.sql.name,
            "source_database": "penx_ci_test",
            "tables": sorted(mb.REQUIRED_TABLES),
            "created_at": "2026-11-04T20:00:00Z",
            "size_bytes": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "capture_method": "mariadb-dump-single-transaction-innodb",
        }
        manifest.update(changes)
        self.meta.write_text(
            json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8",
        )

    def verify(self, path=None, *, sql_pin=None, meta_pin=None):
        return pins.verify_pinned_logical_backup(
            path if path is not None else self.sql,
            expected_sql_sha256=sql_pin if sql_pin is not None
            else self.original_sql_sha,
            expected_manifest_sha256=meta_pin if meta_pin is not None
            else self.original_meta_sha,
        )

    def test_external_pins_accept_both_sql_and_json_entrypoints(self):
        for path in (self.sql, self.meta):
            with self.subTest(path=path):
                info = self.verify(path)
                self.assertEqual(info["status"], "operator-pinned-file-identity-only")
                self.assertEqual(info["sql_sha256"], self.original_sql_sha)
                self.assertEqual(info["manifest_sha256"], self.original_meta_sha)
                self.assertTrue(info["supplied_sql_pin_matches"])
                self.assertTrue(info["supplied_manifest_pin_matches"])
                for field in ("pin_origin_authenticated",
                              "historical_backup_rows_verified",
                              "sql_semantics_verified", "restore_available",
                              "sql_executed", "database_modified"):
                    self.assertFalse(info[field])
                self.assertNotIn("penx_ci_test", json.dumps(info))
                self.assertNotIn("INSERT INTO", json.dumps(info))

    def test_rewritten_sql_and_self_consistent_manifest_fail_old_pin(self):
        self.write_pair(self.original.replace(b"(1)", b"(2)"))
        # The existing adjacent manifest/SQL checks pass after a joint forgery.
        mb.verify_logical_backup(self.sql)
        with self.assertRaisesRegex(ValueError, "pin"):
            self.verify()

    def test_manifest_only_rewrite_is_rejected_even_if_sql_same(self):
        self.write_pair(self.original, source_database="forged_source")
        mb.verify_logical_backup(self.sql)
        self.assertEqual(self.sha(self.sql), self.original_sql_sha)
        with self.assertRaisesRegex(ValueError, "pin"):
            self.verify()

    def test_both_matching_new_pins_are_not_attested_provenance(self):
        self.write_pair(self.original.replace(b"(1)", b"(2)"),
                        source_database="changed_source")
        result = self.verify(sql_pin=self.sha(self.sql),
                             meta_pin=self.sha(self.meta))
        self.assertTrue(result["supplied_sql_pin_matches"])
        self.assertFalse(result["pin_origin_authenticated"])
        self.assertFalse(result["historical_backup_rows_verified"])
        self.assertFalse(result["restore_available"])

    def test_missing_or_wrong_pins_and_extensions_fail_closed(self):
        bad = ("", "0" * 63, "G" * 64, "A" * 64, "0" * 64 + "\n",
               12, True, None, [])
        for value in bad:
            with self.subTest(value=value), self.assertRaises(ValueError):
                pins.verify_pinned_logical_backup(
                    self.sql, expected_sql_sha256=value,
                    expected_manifest_sha256=self.original_meta_sha)
            with self.subTest(meta=value), self.assertRaises(ValueError):
                pins.verify_pinned_logical_backup(
                    self.sql, expected_sql_sha256=self.original_sql_sha,
                    expected_manifest_sha256=value)
        with self.assertRaises(ValueError):
            self.verify(self.root / "backup.csv")

    def test_invalid_missing_and_symlink_manifest_rejected(self):
        self.meta.unlink()
        with self.assertRaises(ValueError):
            self.verify()
        self.write_pair(self.original)
        target = self.root / "real.json"
        self.meta.rename(target)
        try:
            self.meta.symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest("Symlink unavailable")
        with self.assertRaises(ValueError):
            self.verify()

    def test_too_large_and_duplicate_manifest_rejected(self):
        with patch.object(pins, "MAX_MANIFEST_BYTES", 16):
            with self.assertRaises(ValueError):
                self.verify()
        data = self.meta.read_text(encoding="utf-8")
        self.meta.write_text(data.replace(
            '"status": ', '"status": "forged", "status": ', 1),
            encoding="utf-8")
        with self.assertRaises(ValueError):
            # Original pin fails even before duplicate-key parser.
            self.verify(sql_pin=self.sha(self.sql))

    def test_manifest_change_after_existing_verify_is_refused(self):
        actual = pins.verify_logical_backup
        def flip_after_verify(path):
            report = actual(path)
            self.meta.write_text(
                self.meta.read_text(encoding="utf-8") + " ", encoding="utf-8")
            return report
        with patch.object(pins, "verify_logical_backup",
                          side_effect=flip_after_verify):
            with self.assertRaisesRegex(ValueError, "changed"):
                self.verify()

    def test_cli_does_not_echo_pins_or_sql_on_failure(self):
        args = ["mariadb-verify-pinned", "--file", str(self.sql),
                "--sql-sha256", self.original_sql_sha,
                "--manifest-sha256", self.original_meta_sha]
        with redirect_stdout(StringIO()) as output:
            self.assertEqual(backup_cli(args), 0)
        info = json.loads(output.getvalue())
        self.assertEqual(info["status"], "operator-pinned-file-identity-only")
        self.assertFalse(info["restore_available"])
        args[-1] = "a" * 64
        with redirect_stdout(StringIO()) as output:
            self.assertEqual(backup_cli(args), 2)
        self.assertEqual(json.loads(output.getvalue())["status"], "unverified")
        self.assertNotIn(str(self.sql), output.getvalue())
        self.assertNotIn(args[-1], output.getvalue())

    def test_no_database_network_or_subprocess_calls(self):
        with (patch("socket.create_connection",
                    side_effect=AssertionError("opened socket")),
              patch("subprocess.run",
                    side_effect=AssertionError("ran subprocess")),
              patch.object(mb, "_read_only_mariadb_factory",
                           side_effect=AssertionError("connected DB"))):
            info = self.verify()
        self.assertFalse(info["database_modified"])


if __name__ == "__main__":
    unittest.main()
