"""Offline regressions for bugreport F-05 through F-11.

Real disposable SQLite; no production resources, native scanners, or network.
"""
from __future__ import annotations

from contextlib import closing
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch

from penx_app.storage import db, db_evals, db_backend
from penx_app.storage.schema_migrations import initialize_sqlite
from penx_app.scanners import process_runner, tools
from penx_app.domain.scan_models import ScannerOutput
from penx_app.reporting.report_batch import (
    _manifest_path, begin_publication, publication_state,
)


class SQLitePlaceholderTests(unittest.TestCase):
    def test_percent_s_literals_and_comments_are_not_rewritten(self):
        conn = sqlite3.connect(":memory:")
        try:
            cursor = db_backend.SQLiteCursor(conn.cursor())
            cursor.execute("SELECT '%s' AS literal, %s AS param", ("bound",))
            self.assertEqual(cursor.fetchone(), ("%s", "bound"))
            cursor.execute("SELECT 'it''s %s' AS literal, %s -- %s commented\n",
                           (123,))
            self.assertEqual(cursor.fetchone(), ("it's %s", 123))
            cursor.execute('SELECT "%s" AS literal, %s', ("ok",))
            self.assertEqual(cursor.fetchone(), ("%s", "ok"))
            sql = db_backend._sqlite_sql(
                "SELECT `col%s`, [col%s], %s /* %s */, '%s', %s"
            )
            self.assertEqual(sql.count("?"), 2)
            self.assertIn("/* %s */", sql)
            self.assertIn("[col%s]", sql)
        finally:
            conn.close()


class ScannerInputContracts(unittest.TestCase):
    def test_malformed_argv_and_timeout_never_spawn_processes(self):
        invalid = ([], None, "", [""], [None], [False], ["tool", None],
                   ["tool", "bad\x00argument"])
        with patch.object(process_runner.subprocess, "Popen",
                          side_effect=AssertionError("spawned malformed command")) as start:
            for argv in invalid:
                for event in (None, threading.Event()):
                    with self.subTest(argv=argv, cancelled=event is not None):
                        if event is not None:
                            event.set()
                        result = process_runner.run_tool(argv, cancel_event=event)
                        self.assertEqual(result.status, "FAILED")
                        self.assertFalse(result.evidence)
            for timeout in (0, -1, float("inf"), "long", True):
                with self.subTest(timeout=timeout):
                    result = process_runner.run_tool(["safe"], timeout=timeout)
                    self.assertEqual(result.status, "FAILED")
            start.assert_not_called()

    def test_legacy_objects_never_become_scanner_evidence(self):
        for value in (None, False, [], {}, object(), ["443/tcp open"]):
            with self.subTest(value=type(value).__name__):
                result = tools._process_outcome(value)
                self.assertEqual(result.status, "FAILED")
                self.assertFalse(result.evidence)
        self.assertTrue(tools._process_outcome("443/tcp open").evidence)
        typed = ScannerOutput("real fixture", status="COMPLETE", evidence=True)
        self.assertIs(tools._process_outcome(typed), typed)


class DatabaseAndManifestBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="penx-audit-fix-")
        self.addCleanup(self.tmp.cleanup)
        self.folder = Path(self.tmp.name)
        self.path = self.folder / "test.sqlite"
        with closing(sqlite3.connect(self.path)) as conn:
            initialize_sqlite(conn)

    def db(self):
        return db_backend.SQLiteConnection(sqlite3.connect(self.path, timeout=5))

    def test_evaluation_delete_returns_true_only_for_matching_row(self):
        with patch.object(db, "get_connection", side_effect=self.db), \
             patch.object(db_evals, "get_connection", side_effect=self.db):
            session = db.create_session("fixture.test")
            vuln = db.save_vulnerability(session, "observed", "low", "443",
                                         "https", "synthetic")
            evaluation = db_evals.save_evaluation(
                session, vuln, "reviewer", "fixture", "valid", "high",
                True, True, True, True, "fixture",
            )
            self.assertFalse(db_evals.delete_evaluation(evaluation, sl_no=session + 1))
            self.assertTrue(db_evals.delete_evaluation(evaluation, sl_no=session))
            self.assertFalse(db_evals.delete_evaluation(evaluation, sl_no=session))

    def test_full_session_delete_acquires_session_lock(self):
        with patch.object(db, "get_connection", side_effect=self.db):
            session = db.create_session("fixture.test")
            with patch.object(db, "_lock_session_writer",
                              wraps=db._lock_session_writer) as lock:
                db.delete_full_session(session)
            lock.assert_called_once()
            self.assertEqual(lock.call_args.args[1], session)
            self.assertIsNone(db.get_session(session)["history"])

    def test_manifest_reader_rejects_oversize_and_wrong_session(self):
        begin_publication(self.folder, 4, ("html",))
        self.assertEqual(publication_state(self.folder, 4)["status"], "in_progress")
        manifest = _manifest_path(self.folder, 4)
        manifest.write_bytes(b" " * 66000)
        self.assertIsNone(publication_state(self.folder, 4))
        manifest.write_text(
            '{"schema":"penx-publication-v1","session":6,'
            '"status":"in_progress"}', encoding="utf-8",
        )
        self.assertIsNone(publication_state(self.folder, 4))
        manifest.write_text(
            '{"schema":"unknown","session":4,"status":"complete"}',
            encoding="utf-8",
        )
        self.assertIsNone(publication_state(self.folder, 4))


if __name__ == "__main__":
    unittest.main()
