"""Restore SQLite v2 WAL snapshots and exercise the v3 migration contract.

All databases here are disposable, populated only with synthetic fixtures.
The real backup uses SQLite's online backup API while the source WAL is open.
"""
from __future__ import annotations

from contextlib import closing
from pathlib import Path
import sqlite3
import tempfile
import unittest

from penx_app.storage.schema_migrations import SCHEMA, SCHEMA_VERSION, initialize_sqlite


class HistoricalV2WalRestoreTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="penx-v2-wal-")
        self.addCleanup(temp.cleanup)
        self.source = Path(temp.name) / "v2-original.sqlite"
        self.copy = Path(temp.name) / "v2-restored.sqlite"

    def legacy(self, *, invalid: str | None = None):
        conn = sqlite3.connect(self.source)
        self.addCleanup(conn.close)
        self.assertEqual(conn.execute("PRAGMA journal_mode=WAL").fetchone()[0], "wal")
        conn.executescript(SCHEMA + "\nPRAGMA user_version=2;")
        conn.execute("INSERT INTO history (sl_no, target, scan_date) VALUES (7, ?, '2025-01-01')",
                     ("fixture.example.test",))
        conn.execute("INSERT INTO summary (id,sl_no,raw_scan,ai_analysis,risk_level) "
                     "VALUES (9,7,'fixture raw','fixture analysis','LOW')")
        if invalid == "duplicate":
            conn.execute("INSERT INTO summary (id,sl_no,raw_scan) VALUES (10,7,'other')")
        elif invalid == "orphan":
            conn.execute("INSERT INTO summary (id,sl_no,raw_scan) VALUES (10,99,'orphan')")
        elif invalid == "null":
            conn.execute("INSERT INTO summary (id,sl_no,raw_scan) VALUES (10,NULL,'null')")
        conn.commit()
        with closing(sqlite3.connect(self.copy)) as restored:
            conn.backup(restored)
        return conn

    def test_restored_v2_snapshot_migrates_and_guards_writers(self):
        source = self.legacy()
        with closing(sqlite3.connect(self.copy)) as db:
            self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 2)
            initialize_sqlite(db)
            initialize_sqlite(db)  # idempotent
            self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], SCHEMA_VERSION)
            self.assertEqual(db.execute("SELECT sl_no,raw_scan,ai_analysis FROM summary").fetchone(),
                             (7, "fixture raw", "fixture analysis"))
            self.assertIn("uq_summary_sl_no",
                          {row[1] for row in db.execute("PRAGMA index_list(summary)")})
            # The trigger must protect legacy imports even when foreign_keys=OFF.
            self.assertEqual(db.execute("PRAGMA foreign_keys").fetchone()[0], 0)
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute("INSERT INTO summary (sl_no) VALUES (NULL)")
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute("INSERT INTO summary (sl_no) VALUES (999)")
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute("INSERT INTO summary (sl_no) VALUES (7)")
            db.rollback()
            self.assertEqual(db.execute("SELECT COUNT(*) FROM summary").fetchone()[0], 1)
        self.assertEqual(source.execute("PRAGMA user_version").fetchone()[0], 2)
        self.assertEqual(source.execute("SELECT COUNT(*) FROM summary").fetchone()[0], 1)

    def test_bad_v2_snapshots_roll_back_without_data_loss_and_can_retry(self):
        for invalid in ("duplicate", "orphan", "null"):
            with self.subTest(invalid=invalid):
                # Each scenario needs its own WAL database and backup file.
                self.source.unlink(missing_ok=True)
                self.copy.unlink(missing_ok=True)
                self.source = self.source.with_name(f"v2-{invalid}.sqlite")
                self.copy = self.copy.with_name(f"v2-{invalid}-restored.sqlite")
                self.legacy(invalid=invalid)
                with closing(sqlite3.connect(self.copy)) as db:
                    before = db.execute("SELECT id, sl_no, raw_scan FROM summary ORDER BY id").fetchall()
                    with self.assertRaisesRegex(ValueError, "migration v3 blocked"):
                        initialize_sqlite(db)
                    self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 2)
                    self.assertEqual(db.execute("SELECT id, sl_no, raw_scan FROM summary ORDER BY id").fetchall(), before)
                    self.assertNotIn("uq_summary_sl_no",
                                     {row[1] for row in db.execute("PRAGMA index_list(summary)")})
                    db.execute("DELETE FROM summary WHERE id=10")
                    db.commit()
                    initialize_sqlite(db)
                    self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], SCHEMA_VERSION)
                    self.assertEqual(db.execute("SELECT id,sl_no FROM summary").fetchall(), [(9, 7)])

    def test_future_schema_is_rejected_without_modifying_database(self):
        self.legacy()
        with closing(sqlite3.connect(self.copy)) as db:
            db.execute("PRAGMA user_version=999")
            with self.assertRaisesRegex(ValueError, "Unsupported database schema version"):
                initialize_sqlite(db)
            self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 999)
            self.assertEqual(db.execute("SELECT raw_scan FROM summary").fetchone()[0],
                             "fixture raw")


if __name__ == "__main__":
    unittest.main()
