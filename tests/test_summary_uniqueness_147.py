"""Offline SQLite v3 migration: unique summary/session and safe legacy upgrades."""
from __future__ import annotations

import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from penx_app.storage.schema_migrations import SCHEMA, SCHEMA_VERSION, initialize_sqlite
from scripts.audit_summary_uniqueness import audit_database


class SummaryUniquenessMigrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="penx-147-schema-")
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "penx.sqlite"

    def legacy_v2(self):
        conn = sqlite3.connect(self.path)
        self.addCleanup(conn.close)
        conn.executescript(SCHEMA)
        conn.execute("ALTER TABLE summary ADD COLUMN scan_metadata TEXT DEFAULT ''")
        conn.execute("PRAGMA user_version = 2")
        conn.execute("INSERT INTO history (sl_no,target,scan_date) "
                     "VALUES (7, 'fixture.test', '2026-10-15')")
        conn.commit()
        return conn

    @staticmethod
    def write_summary(conn, session=7, raw="first"):
        conn.execute(
            "INSERT INTO summary (sl_no,raw_scan,ai_analysis,risk_level) "
            "VALUES (?,?,?,?)", (session, raw, "synthetic", "LOW")
        )
        conn.commit()

    def test_fresh_schema_uses_unique_index_and_rejects_invalid_ids(self):
        with closing(sqlite3.connect(self.path)) as conn:
            initialize_sqlite(conn)
            self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], 3)
            self.assertEqual(SCHEMA_VERSION, 3)
            indexes = {row[1] for row in conn.execute("PRAGMA index_list(summary)")}
            self.assertIn("uq_summary_sl_no", indexes)
            conn.execute("INSERT INTO history (sl_no,target,scan_date) "
                         "VALUES (7,'fixture.test','2026-10-15')")
            conn.execute("INSERT INTO summary (sl_no,raw_scan) VALUES (7,'good')")
            conn.commit()
            for bad in (7, None, 890):
                with self.subTest(sl_no=bad), self.assertRaises(sqlite3.IntegrityError):
                    conn.execute("INSERT INTO summary (sl_no,raw_scan) VALUES (?, 'bad')", (bad,))
            conn.rollback()
            self.assertEqual(conn.execute(
                "SELECT COUNT(*) FROM summary WHERE sl_no=7"
            ).fetchone()[0], 1)

    def test_valid_legacy_v2_upgrade_preserves_summary_and_is_idempotent(self):
        conn = self.legacy_v2()
        self.write_summary(conn)
        before = conn.execute(
            "SELECT id,sl_no,raw_scan FROM summary"
        ).fetchall()
        initialize_sqlite(conn)
        initialize_sqlite(conn)
        self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], 3)
        self.assertEqual(conn.execute(
            "SELECT id,sl_no,raw_scan FROM summary"
        ).fetchall(), before)
        with self.assertRaises(sqlite3.IntegrityError):
            conn.execute("INSERT INTO summary (sl_no,raw_scan) VALUES (7,'duplicate')")

    def test_legacy_duplicate_blocks_entire_migration_and_allows_reviewed_retry(self):
        conn = self.legacy_v2()
        self.write_summary(conn, raw="first")
        self.write_summary(conn, raw="second")
        before = conn.execute("SELECT id,raw_scan FROM summary ORDER BY id").fetchall()
        with self.assertRaisesRegex(ValueError, "duplicate summary"):
            initialize_sqlite(conn)
        self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], 2)
        self.assertEqual(conn.execute(
            "SELECT id,raw_scan FROM summary ORDER BY id"
        ).fetchall(), before)
        self.assertNotIn("uq_summary_sl_no", {
            row[1] for row in conn.execute("PRAGMA index_list(summary)")
        })
        self.assertEqual(audit_database(self.path)["duplicates"], [(7, 2)])
        # Synthetic fixture only: an operator has explicitly reviewed row 2.
        conn.execute("DELETE FROM summary WHERE id=?", (before[1][0],))
        conn.commit()
        initialize_sqlite(conn)
        self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], 3)

    def test_null_session_id_blocks_upgrade_without_data_loss(self):
        conn = self.legacy_v2()
        self.write_summary(conn, session=None, raw="invalid")
        with self.assertRaisesRegex(ValueError, "NULL session ID"):
            initialize_sqlite(conn)
        self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], 2)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM summary").fetchone()[0], 1)
        self.assertTrue(audit_database(self.path)["null_session_ids"])

    def test_orphan_session_id_blocks_upgrade_without_data_loss(self):
        conn = self.legacy_v2()
        self.write_summary(conn, session=91, raw="orphan")
        with self.assertRaisesRegex(ValueError, "orphan summary"):
            initialize_sqlite(conn)
        self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], 2)
        self.assertEqual(conn.execute(
            "SELECT sl_no,raw_scan FROM summary"
        ).fetchone(), (91, "orphan"))
        self.assertEqual(audit_database(self.path)["orphan_summaries"][0][1], 91)

    def test_audit_is_read_only_and_valid_database_is_clean(self):
        conn = self.legacy_v2()
        self.write_summary(conn)
        before = self.path.read_bytes()
        self.assertEqual(audit_database(self.path), {
            "duplicates": [], "null_session_ids": [], "orphan_summaries": [],
        })
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], 2)


if __name__ == "__main__":
    unittest.main()
