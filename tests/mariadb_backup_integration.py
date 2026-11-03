"""Gated disposable MariaDB backup/restore; NEVER use production databases."""
from __future__ import annotations
from contextlib import redirect_stdout
from io import StringIO
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

from penx_app.application import mariadb_backup
from penx_app.application.backup_service import main as backup_main
from penx_app.storage import db, db_backend

RESTORE_DB = "penx_ci_native_restore_test"


class MariaDBLogicalBackupIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        service = os.getenv("PENX_MARIADB_CONTAINER", "")
        if not (os.getenv("PENX_MARIADB_TEST") == "1"
                and db_backend.DB_ENGINE == "mariadb"
                and db_backend.DB_HOST == "127.0.0.1"
                and db_backend.DB_NAME == "penx_ci_test"
                and db_backend.DB_USER == "penx_ci"
                and db_backend.DB_PASSWORD == "integration-only"
                and re.fullmatch(r"[a-f0-9]{12,64}", service)):
            raise RuntimeError("REFUSED: isolated CI MariaDB service required")
        cls.container = service

    @classmethod
    def root_query(cls, *args, stdin_file=None):
        command = ["docker", "exec", "-i", cls.container, "mariadb",
                   "--no-defaults", "--protocol=TCP", "--host=127.0.0.1",
                   "--user=root", "--password=integration-root-only", *args]
        if stdin_file is None:
            result = subprocess.run(command, capture_output=True,
                                    check=True, timeout=60)
        else:
            with stdin_file.open("rb") as source:
                result = subprocess.run(
                    command, stdin=source, capture_output=True,
                    check=True, timeout=60)
        return result.stdout.decode("utf-8").strip()

    def test_native_dump_restores_to_new_disposable_schema(self):
        sl = db.create_session("native-backup-fixture.invalid", status="pending")
        try:
            db.save_assessment(sl, {
                "risk_level": "LOW",
                "raw_scan": "Owned MariaDB backup fixture only",
                "full_response": "No external scanner or target",
                "vulnerabilities": [], "recommendations": [], "exploits": [],
            }, model_name="fixture-no-AI")
            with tempfile.TemporaryDirectory(prefix="penx-native-dump-") as tmp:
                output = Path(tmp)
                created = mariadb_backup.create_logical_backup(
                    host="127.0.0.1", port=3306, database="penx_ci_test",
                    user="penx_ci", password="integration-only",
                    directory=output)
                self.assertEqual(created["status"],
                                 "verified-file-integrity-only")
                self.assertGreater(created["tables_in_manifest"], 6)
                sql = output / created["file"]
                self.assertEqual(mariadb_backup.verify_logical_backup(sql), created)
                self.assertFalse(mariadb_backup.preview_logical_backup(
                    sql)["restore_available"])
                # This target is exclusively a fresh scratch schema in a
                # GitHub Actions service container, never the source database.
                self.root_query("-e", "CREATE DATABASE " + RESTORE_DB +
                                " CHARACTER SET utf8mb4")
                self.root_query(RESTORE_DB, stdin_file=sql)
                queries = [
                    "SELECT COUNT(*) FROM " + RESTORE_DB +
                    ".history WHERE sl_no=" + str(sl) +
                    " AND target='native-backup-fixture.invalid'",
                    "SELECT COUNT(*) FROM " + RESTORE_DB +
                    ".summary WHERE sl_no=" + str(sl) + " AND risk_level='LOW'",
                    "SELECT COUNT(*) FROM information_schema.STATISTICS "
                    "WHERE TABLE_SCHEMA='" + RESTORE_DB +
                    "' AND TABLE_NAME='summary' "
                    "AND INDEX_NAME='uq_summary_sl_no' AND NON_UNIQUE=0",
                ]
                self.assertEqual(
                    [self.root_query("-N", "-B", "-e", q) for q in queries],
                    ["1", "1", "1"])
                with redirect_stdout(StringIO()) as stream:
                    self.assertEqual(backup_main([
                        "mariadb-verify", "--file", str(sql)]), 0)
                    self.assertEqual(backup_main([
                        "mariadb-preview", "--file", str(sql)]), 0)
                rows = [json.loads(line) for line in stream.getvalue().splitlines()]
                self.assertEqual(len(rows), 2)
                self.assertFalse(rows[1]["restore_available"])
                self.assertNotIn("integration-only", stream.getvalue())
                with sql.open("ab") as stream:
                    stream.write(b"\n-- tampered after backup\n")
                with self.assertRaises(ValueError):
                    mariadb_backup.verify_logical_backup(sql)
        finally:
            db.delete_full_session(sl)


if __name__ == "__main__":
    unittest.main(verbosity=2)

