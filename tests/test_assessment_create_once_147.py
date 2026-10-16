"""Prevent repeated save requests from duplicating assessment history (#147)."""
from __future__ import annotations

import sqlite3
import tempfile
import threading
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from penx_app.storage import db
from penx_app.storage.db_backend import SQLiteConnection
from penx_app.storage.schema_migrations import initialize_sqlite


def assessment():
    return {
        "vulnerabilities": [{"vuln_name": "fixture", "severity": "low",
                             "confidence": "possible", "description": "offline"}],
        "recommendations": [], "exploits": [], "raw_scan": "test-only",
        "full_response": "fixture", "risk_level": "LOW",
    }


class CreateOnceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="penx-create-once-")
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "db.sqlite"
        with closing(sqlite3.connect(self.path)) as con:
            initialize_sqlite(con)

    def connect(self):
        return SQLiteConnection(sqlite3.connect(self.path, timeout=15))

    def count(self, table, sl):
        with closing(sqlite3.connect(self.path)) as con:
            return con.execute("SELECT COUNT(*) FROM " + table + " WHERE sl_no = ?",
                               (sl,)).fetchone()[0]

    def test_assessment_double_save_fails_atomically_before_child_inserts(self):
        with patch.object(db, "get_connection", side_effect=self.connect):
            sl = db.create_session("example.test", status="pending")
            db.save_assessment(sl, assessment(), model_name="offline")
            before = (self.count("summary", sl), self.count("vulnerabilities", sl))
            with self.assertRaisesRegex(ValueError, "already exists"):
                db.save_assessment(sl, assessment(), model_name="offline")
            self.assertEqual(before, (1, 1))
            self.assertEqual(before,
                             (self.count("summary", sl), self.count("vulnerabilities", sl)))

    def test_legacy_summary_and_new_assessment_cannot_duplicate(self):
        with patch.object(db, "get_connection", side_effect=self.connect):
            sl = db.create_session("example.test")
            db.save_summary(sl, "scan", "review", "LOW", "offline")
            with self.assertRaisesRegex(ValueError, "already exists"):
                db.save_summary(sl, "later scan", "review", "HIGH", "offline")
            with self.assertRaisesRegex(ValueError, "already exists"):
                db.save_assessment(sl, assessment(), model_name="offline")
        self.assertEqual(self.count("summary", sl), 1)
        self.assertEqual(self.count("vulnerabilities", sl), 0)

    def test_two_simultaneous_summary_writers_create_only_one(self):
        with patch.object(db, "get_connection", side_effect=self.connect):
            sl = db.create_session("example.test")
            gate = threading.Barrier(2)
            completed = []
            errors = []

            def save():
                gate.wait(timeout=10)
                try:
                    db.save_summary(sl, "scan", "analysis", "LOW", "fixture")
                    completed.append(True)
                except ValueError as exc:
                    errors.append(str(exc))

            threads = [threading.Thread(target=save) for _ in range(2)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=20)
            self.assertFalse(any(t.is_alive() for t in threads))
            self.assertEqual(len(completed), 1)
            self.assertEqual(len(errors), 1)
            self.assertIn("already exists", errors[0])
        self.assertEqual(self.count("summary", sl), 1)


if __name__ == "__main__":
    unittest.main()
