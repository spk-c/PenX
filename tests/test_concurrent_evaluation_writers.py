"""Simultaneous evaluation imports must never create duplicate records.

Use separate real SQLite connections on WAL and deterministic thread events.
No network calls or customer data.
"""
from __future__ import annotations

from contextlib import closing
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch

from penx_app.storage import db_evals
from penx_app.storage.db_backend import SQLiteConnection, SQLiteCursor
from penx_app.storage.schema_migrations import initialize_sqlite


REVIEW = (
    "EVAL: Synthetic finding\n"
    "VERDICT: hallucination\n"
    "CONFIDENCE: high\n"
    "EVIDENCE: Synthetic observation only\n"
    "SEVERITY_CORRECT: no\n"
    "CVE_CORRECT: no\n"
    "SOFTWARE_CORRECT: no\n"
    "FIX_CORRECT: no\n"
    "NOTES: Duplicate evaluation stress fixture\n"
)


class ProbeCursor:
    def __init__(self, wrapped: SQLiteCursor, pause_callback, selected_callback):
        self.wrapped = wrapped
        self.pause_callback = pause_callback
        self.selected_callback = selected_callback
        self.selection = False

    def execute(self, sql, params=()):
        self.selection = "FROM vulnerabilities WHERE sl_no" in sql
        self.wrapped.execute(sql, params)
        return self

    def fetchone(self):
        return self.wrapped.fetchone()

    def fetchall(self):
        rows = self.wrapped.fetchall()
        if self.selection:
            self.selected_callback()
            self.pause_callback()
        return rows

    def __getattr__(self, name):
        return getattr(self.wrapped, name)


class ProbeConnection(SQLiteConnection):
    def __init__(self, connection, pause_callback, selected_callback):
        super().__init__(connection)
        self.pause_callback = pause_callback
        self.selected_callback = selected_callback

    def cursor(self):
        return ProbeCursor(
            super().cursor(), self.pause_callback, self.selected_callback
        )


class ConcurrentEvaluationImportTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="penx-eval-writer-")
        self.addCleanup(tmp.cleanup)
        self.db_path = Path(tmp.name) / "assessment.sqlite"
        with closing(sqlite3.connect(self.db_path)) as db:
            self.assertEqual(db.execute("PRAGMA journal_mode=WAL").fetchone()[0], "wal")
            initialize_sqlite(db)
            db.execute(
                "INSERT INTO history (sl_no,target,scan_date,status) "
                "VALUES (1,'synthetic.test','2026-10-17','active')"
            )
            db.execute(
                "INSERT INTO vulnerabilities (id,sl_no,vuln_name,severity,confidence) "
                "VALUES (10,1,'Synthetic finding','medium','possible')"
            )
            db.commit()

    def count(self):
        with closing(sqlite3.connect(self.db_path)) as db:
            return (
                db.execute("SELECT COUNT(*) FROM evaluations").fetchone()[0],
                db.execute("SELECT COUNT(*) FROM corrections").fetchone()[0],
            )

    def test_two_concurrent_identical_imports_save_once_without_lock_errors(self):
        first_selected = threading.Event()
        release_first = threading.Event()
        second_entered = threading.Event()
        second_selected = threading.Event()
        results = {}
        failures = []

        def connection_factory():
            first = threading.current_thread().name == "evaluation-first"
            if not first:
                second_entered.set()
            db = sqlite3.connect(self.db_path, timeout=5)
            db.execute("PRAGMA busy_timeout=5000")
            return ProbeConnection(
                db,
                (lambda: release_first.wait(5)) if first else (lambda: None),
                first_selected.set if first else second_selected.set,
            )

        def worker(name):
            try:
                results[name] = db_evals.parse_evaluation_response(
                    1, "external-fixture", REVIEW
                )
            except BaseException as exc:
                failures.append(exc)

        with patch.object(db_evals, "get_connection", side_effect=connection_factory):
            first = threading.Thread(target=worker, name="evaluation-first",
                                     args=("first",), daemon=True)
            second = threading.Thread(target=worker, name="evaluation-second",
                                      args=("second",), daemon=True)
            first.start()
            try:
                self.assertTrue(first_selected.wait(5), "First importer did not read findings")
                second.start()
                self.assertTrue(second_entered.wait(5), "Second importer did not start")
                # While first importer holds the per-session writer lock, the
                # second must not reach its identity/duplicate checks.
                self.assertFalse(second_selected.wait(0.25),
                                 "Second importer read before first committed")
            finally:
                release_first.set()
                first.join(8)
                if second.ident is not None:
                    second.join(8)

        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertEqual(failures, [])
        self.assertEqual(len(results["first"]), 1)
        self.assertEqual(results["second"], [])
        self.assertEqual(self.count(), (1, 1))

    def test_import_does_not_create_orphan_evaluations_for_missing_session(self):
        with patch.object(db_evals, "get_connection",
                          side_effect=lambda: SQLiteConnection(
                              sqlite3.connect(self.db_path))):
            with self.assertRaisesRegex(ValueError, "session does not exist"):
                db_evals.parse_evaluation_response(999, "fixture", REVIEW)
        self.assertEqual(self.count(), (0, 0))


if __name__ == "__main__":
    unittest.main()
