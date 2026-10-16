"""Synthetic legacy SQLite WAL backup/restore and migration recovery tests.

Uses disposable local fixture databases only. No network, customer data,
model calls or schema migrations against a user's real PenX installation.
"""
from __future__ import annotations

from contextlib import closing
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from penx_app.storage import schema_migrations
from penx_app.storage.db_backend import VULNERABILITY_COLUMNS


class SqliteWalRestoreContracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="penx-wal-restore-")
        self.addCleanup(self.temp.cleanup)
        self.source = Path(self.temp.name) / "old-schema.sqlite"
        self.restored = Path(self.temp.name) / "restored.sqlite"

    def make_legacy_database(self):
        source = sqlite3.connect(self.source)
        self.addCleanup(source.close)
        self.assertEqual(source.execute("PRAGMA journal_mode=WAL").fetchone()[0], "wal")
        source.executescript("""
            CREATE TABLE history (
                sl_no INTEGER PRIMARY KEY,
                target TEXT NOT NULL,
                scan_date TEXT NOT NULL
            );
            CREATE TABLE vulnerabilities (
                id INTEGER PRIMARY KEY,
                sl_no INTEGER,
                vuln_name TEXT,
                severity TEXT,
                port TEXT,
                service TEXT,
                description TEXT
            );
            CREATE TABLE summary (
                id INTEGER PRIMARY KEY,
                sl_no INTEGER,
                raw_scan TEXT,
                ai_analysis TEXT,
                risk_level TEXT,
                generated_at TEXT
            );
            INSERT INTO history VALUES (4, 'fixture.example.test', '2025-04-01');
            INSERT INTO vulnerabilities VALUES
                (14, 4, 'legacy observation', 'low', '443', 'https', 'fixture evidence');
            INSERT INTO summary VALUES
                (24, 4, 'raw fixture', 'review fixture', 'LOW', '2025-04-01');
        """)
        source.commit()
        self.assertEqual(source.execute("PRAGMA user_version").fetchone()[0], 0)
        return source

    def backup_open_wal(self, source):
        # SQLite backup API captures committed WAL pages as well as main DB.
        with closing(sqlite3.connect(self.restored)) as target:
            source.backup(target)
        self.assertTrue(self.restored.is_file())

    def test_restored_legacy_wal_snapshot_migrates_and_preserves_rows(self):
        source = self.make_legacy_database()
        self.backup_open_wal(source)
        with closing(sqlite3.connect(self.restored)) as restored:
            schema_migrations.initialize_sqlite(restored)
            schema_migrations.initialize_sqlite(restored)
            self.assertEqual(
                restored.execute("PRAGMA user_version").fetchone()[0],
                schema_migrations.SCHEMA_VERSION,
            )
            self.assertEqual(
                restored.execute("SELECT target, status FROM history WHERE sl_no=4").fetchone(),
                ("fixture.example.test", "active"),
            )
            self.assertEqual(
                restored.execute(
                    f"SELECT {VULNERABILITY_COLUMNS} FROM vulnerabilities WHERE id=14"
                ).fetchone(),
                (14, 4, "legacy observation", "low", "possible", "443", "https", "fixture evidence"),
            )
            self.assertEqual(
                restored.execute(
                    "SELECT model_name, scan_metadata FROM summary WHERE id=24"
                ).fetchone(),
                ("", ""),
            )
        # Migrating the restored copy must never modify the legacy source.
        self.assertEqual(source.execute("PRAGMA user_version").fetchone()[0], 0)
        self.assertNotIn(
            "confidence",
            {row[1] for row in source.execute("PRAGMA table_info(vulnerabilities)")},
        )

    def test_failed_restored_wal_migration_rolls_back_ddl_and_allows_retry(self):
        source = self.make_legacy_database()
        self.backup_open_wal(source)
        with closing(sqlite3.connect(self.restored)) as conn:
            with patch.object(
                schema_migrations, "SCHEMA", schema_migrations.SCHEMA + "\nINVALID SQL;"
            ):
                with self.assertRaises(sqlite3.Error):
                    schema_migrations.initialize_sqlite(conn)
            self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], 0)
            self.assertNotIn(
                "confidence",
                {row[1] for row in conn.execute("PRAGMA table_info(vulnerabilities)")},
            )
            self.assertEqual(
                conn.execute("SELECT target FROM history WHERE sl_no=4").fetchone()[0],
                "fixture.example.test",
            )
            # Successful retry resumes only from the untouched legacy snapshot.
            schema_migrations.initialize_sqlite(conn)
            self.assertEqual(
                conn.execute("PRAGMA user_version").fetchone()[0],
                schema_migrations.SCHEMA_VERSION,
            )


if __name__ == "__main__":
    unittest.main()
