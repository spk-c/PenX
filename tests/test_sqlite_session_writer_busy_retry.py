"""SQLite writer retries are bounded, selective, and before data inserts.

No real targets or persistent user databases. Real WAL conflicts use two
independent SQLite connections and deterministic synchronization events.
"""
from __future__ import annotations

from contextlib import closing
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from penx_app.storage import db, db_evals
from penx_app.storage.db_backend import SQLiteConnection, SQLiteCursor
from penx_app.storage.schema_migrations import initialize_sqlite


class ProbeCursor(SQLiteCursor):
    def __init__(self, cursor, counter, busy_event=None):
        super().__init__(cursor)
        self.counter = counter
        self.busy_event = busy_event

    def execute(self, sql, params=()):
        if sql.startswith("UPDATE history SET status = status"):
            self.counter.append(sql)
        try:
            return super().execute(sql, params)
        except sqlite3.OperationalError as exc:
            if (self.busy_event is not None
                    and getattr(exc, "sqlite_errorcode", None) == sqlite3.SQLITE_BUSY):
                self.busy_event.set()
            raise


class ProbeConnection(SQLiteConnection):
    def __init__(self, connection, counter, busy_event=None):
        super().__init__(connection)
        self.counter = counter
        self.busy_event = busy_event

    def cursor(self):
        return ProbeCursor(self._connection.cursor(), self.counter, self.busy_event)


class FakeCommittedBusy(ProbeConnection):
    def commit(self):
        self._connection.commit()
        exc = sqlite3.OperationalError("database is locked (simulated post-commit)")
        exc.sqlite_errorcode = sqlite3.SQLITE_BUSY
        raise exc


class SqliteSessionLockRetryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="penx-busy-retries-")
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "fixture.sqlite"
        with closing(sqlite3.connect(self.path)) as conn:
            self.assertEqual(conn.execute("PRAGMA journal_mode=WAL").fetchone()[0], "wal")
            initialize_sqlite(conn)
            conn.execute(
                "INSERT INTO history(sl_no,target,scan_date,status) "
                "VALUES (1,'fixture.test','today','active')"
            )
            conn.execute(
                "INSERT INTO vulnerabilities(id,sl_no,vuln_name,severity) "
                "VALUES (11,1,'fixture finding','medium')"
            )
            conn.commit()

    def connection(self, counter, timeout=0.02, factory=ProbeConnection, busy_event=None):
        conn = sqlite3.connect(self.path, timeout=timeout)
        conn.execute("PRAGMA foreign_keys=ON")
        return factory(conn, counter, busy_event)

    def rows(self, table):
        with closing(sqlite3.connect(self.path)) as conn:
            return conn.execute("SELECT COUNT(*) FROM " + table).fetchone()[0]

    def blocker(self):
        entered = threading.Event()
        release = threading.Event()
        failures = []

        def hold():
            try:
                with closing(sqlite3.connect(self.path, timeout=3)) as conn:
                    conn.execute("BEGIN IMMEDIATE")
                    conn.execute("UPDATE history SET status=status WHERE sl_no=1")
                    entered.set()
                    if not release.wait(8):
                        raise AssertionError("Fixture blocker not released")
                    conn.rollback()
            except BaseException as exc:
                failures.append(exc)

        worker = threading.Thread(target=hold, daemon=True)
        worker.start()
        self.assertTrue(entered.wait(4))
        return release, worker, failures

    def test_short_busy_lock_retries_then_saves_exactly_once(self):
        attempts = []
        release, blocker, errors = self.blocker()
        busy = threading.Event()
        releaser = threading.Thread(
            target=lambda: (busy.wait(5), time.sleep(0.07), release.set()),
            daemon=True,
        )
        releaser.start()
        try:
            with patch.object(db, "get_connection",
                              side_effect=lambda: self.connection(attempts, busy_event=busy)):
                identifier = db.save_correction(
                    1, 11, "verified", "old", "", "synthetic retry",
                )
        finally:
            release.set()
            blocker.join(6)
            releaser.join(6)
        self.assertEqual(errors, [])
        self.assertIsInstance(identifier, int)
        self.assertGreater(len(attempts), 1)
        self.assertEqual(self.rows("corrections"), 1)

    def test_permanent_busy_fails_within_budget_without_partial_writes(self):
        attempts = []
        release, blocker, errors = self.blocker()
        try:
            started = time.monotonic()
            with patch.object(db, "get_connection",
                              side_effect=lambda: self.connection(attempts)):
                with self.assertRaises(sqlite3.OperationalError) as failure:
                    db.save_fix(1, 11, "synthetic fix")
            self.assertEqual(failure.exception.sqlite_errorcode, sqlite3.SQLITE_BUSY)
            self.assertLess(time.monotonic() - started, 2.5)
            self.assertGreater(len(attempts), 1)
            self.assertEqual(self.rows("fixes"), 0)
        finally:
            release.set()
            blocker.join(6)
        self.assertEqual(errors, [])
        with patch.object(db, "get_connection",
                          side_effect=lambda: self.connection([])):
            db.save_fix(1, 11, "works after release")
        self.assertEqual(self.rows("fixes"), 1)

    def test_nonbusy_and_busy_snapshot_errors_are_not_replayed(self):
        for code in (sqlite3.SQLITE_ERROR, sqlite3.SQLITE_BUSY_SNAPSHOT):
            with self.subTest(code=code):
                class ErrorCursor:
                    def __init__(self):
                        self.attempts = 0
                    def execute(self, _sql, _params):
                        self.attempts += 1
                        exc = sqlite3.OperationalError("synthetic sqlite error")
                        exc.sqlite_errorcode = code
                        raise exc
                cursor = ErrorCursor()
                with self.assertRaises(sqlite3.OperationalError):
                    db._lock_session_writer(cursor, 1)
                self.assertEqual(cursor.attempts, 1)

    def test_sqlite_commit_failure_is_never_replayed(self):
        attempts = []
        with patch.object(db, "get_connection",
                          side_effect=lambda: self.connection(
                              attempts, factory=FakeCommittedBusy)):
            with self.assertRaisesRegex(sqlite3.OperationalError, "post-commit"):
                db.save_correction(1, 11, "verified", "", "", "only once")
        self.assertEqual(len(attempts), 1)
        self.assertEqual(self.rows("corrections"), 1)

    def test_evaluation_parser_reuses_session_lock_retry(self):
        attempts = []
        response = (
            "EVAL: fixture finding\n"
            "VERDICT: valid\n"
            "CONFIDENCE: high\n"
            "EVIDENCE: synthetic\n"
            "SEVERITY_CORRECT: yes\n"
            "CVE_CORRECT: yes\n"
            "SOFTWARE_CORRECT: yes\n"
            "FIX_CORRECT: yes\n"
            "NOTES: evidence fixture\n"
        )
        release, blocker, errors = self.blocker()
        releaser = threading.Thread(
            target=lambda: (time.sleep(0.15), release.set()), daemon=True,
        )
        releaser.start()
        try:
            with patch.object(db_evals, "get_connection",
                              side_effect=lambda: self.connection(attempts, busy_event=busy)):
                saved = db_evals.parse_evaluation_response(1, "fixture", response)
        finally:
            release.set()
            blocker.join(6)
            releaser.join(6)
        self.assertEqual(errors, [])
        self.assertEqual(len(saved), 1)
        self.assertGreater(len(attempts), 1)
        self.assertEqual(self.rows("evaluations"), 1)


if __name__ == "__main__":
    unittest.main()
