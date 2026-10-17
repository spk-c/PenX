"""Concurrent finding deletes and child writes must serialize, not race.

All operations use disposable SQLite WAL databases and real independent
connections; nothing reaches user databases or scan targets.
"""
from __future__ import annotations

from contextlib import closing
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch

from penx_app.storage import db, db_evals
from penx_app.storage.db_backend import SQLiteConnection
from penx_app.storage.schema_migrations import initialize_sqlite


class PausingCursor:
    def __init__(self, cursor, pause):
        self.cursor = cursor
        self.pause = pause
        self.owner_select = False

    def execute(self, sql, params=()):
        self.owner_select = sql.startswith(
            "SELECT id FROM vulnerabilities WHERE id = %s AND sl_no = %s"
        )
        self.cursor.execute(sql, params)
        return self

    def fetchone(self):
        value = self.cursor.fetchone()
        if self.owner_select:
            self.owner_select = False
            self.pause()
        return value

    def __getattr__(self, name):
        return getattr(self.cursor, name)


class PausingConnection(SQLiteConnection):
    def __init__(self, raw, pause):
        super().__init__(raw)
        self.pause = pause

    def cursor(self):
        return PausingCursor(super().cursor(), self.pause)


class FindingWriterRaceTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="penx-writer-race-")
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / "database.sqlite"
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

    def connection(self, *, timeout=5, pause=lambda: None):
        raw = sqlite3.connect(self.path, timeout=timeout)
        raw.execute("PRAGMA foreign_keys=ON")
        raw.execute("PRAGMA busy_timeout=%d" % int(timeout * 1000))
        return PausingConnection(raw, pause)

    def counts(self):
        with closing(sqlite3.connect(self.path)) as conn:
            return {
                table: conn.execute("SELECT COUNT(*) FROM " + table).fetchone()[0]
                for table in ("vulnerabilities", "fixes", "corrections", "evaluations")
            }

    @staticmethod
    def child_writers():
        return {
            "fix": lambda: db.save_fix(1, 11, "synthetic mitigation"),
            "correction": lambda: db.save_correction(
                1, 11, "verified", "old text", "", "synthetic evidence"),
            "evaluation": lambda: db_evals.save_evaluation(
                1, 11, "synthetic", "fixture", "valid", "high",
                True, True, True, True, "test notes"),
        }

    def test_child_inserts_lock_out_concurrent_finding_deletion(self):
        for name, write in self.child_writers().items():
            with self.subTest(writer=name):
                self._run_writer_before_delete(write)
                # Restore the finding for the next isolated subcase.
                with closing(sqlite3.connect(self.path)) as conn:
                    conn.execute(
                        "INSERT INTO vulnerabilities(id,sl_no,vuln_name,severity) "
                        "VALUES (11,1,'fixture finding','medium')"
                    )
                    conn.commit()

    def _run_writer_before_delete(self, write):
        entered = threading.Event()
        release = threading.Event()
        delete_connected = threading.Event()
        done_delete = threading.Event()
        outcomes = {}
        failures = []

        def paused():
            entered.set()
            if not release.wait(8):
                raise AssertionError("writer fixture was not released")

        def factory():
            is_first = threading.current_thread().name == "child-first"
            if not is_first:
                delete_connected.set()
            return self.connection(pause=paused if is_first else lambda: None)

        def worker(label, fn):
            try:
                outcomes[label] = fn()
            except BaseException as exc:
                failures.append(exc)
            finally:
                if label == "delete":
                    done_delete.set()

        with patch.object(db, "get_connection", side_effect=factory), \
             patch.object(db_evals, "get_connection", side_effect=factory):
            first = threading.Thread(
                target=worker, args=("write", write), name="child-first", daemon=True)
            second = threading.Thread(
                target=worker,
                args=("delete", lambda: db.delete_vulnerability(11, sl_no=1)),
                name="delete-second", daemon=True,
            )
            first.start()
            try:
                self.assertTrue(entered.wait(5), "Child owner query did not start")
                second.start()
                self.assertTrue(delete_connected.wait(5))
                self.assertFalse(done_delete.wait(0.2),
                                 "Finding deletion bypassed child-writer lock")
            finally:
                release.set()
                first.join(8)
                if second.ident is not None:
                    second.join(8)

        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertEqual(failures, [])
        self.assertIn("write", outcomes)
        self.assertTrue(outcomes["delete"])
        self.assertEqual(self.counts(), {
            "vulnerabilities": 0, "fixes": 0,
            "corrections": 0, "evaluations": 0,
        })

    def test_delete_first_avoids_stale_owner_and_foreign_key_error(self):
        entered = threading.Event()
        release = threading.Event()
        insert_connected = threading.Event()
        insert_done = threading.Event()
        outcome = {}
        failures = []

        def first_pause():
            entered.set()
            if not release.wait(8):
                raise AssertionError("deletion fixture was not released")

        def factory():
            is_delete = threading.current_thread().name == "delete-first"
            if not is_delete:
                insert_connected.set()
            return self.connection(pause=first_pause if is_delete else lambda: None)

        def delete():
            try:
                outcome["deleted"] = db.delete_vulnerability(11, sl_no=1)
            except BaseException as exc:
                failures.append(exc)

        def insert():
            try:
                db.save_correction(1, 11, "verified", "", "", "late write")
                outcome["inserted"] = True
            except BaseException as exc:
                outcome["insert_error"] = exc
            finally:
                insert_done.set()

        with patch.object(db, "get_connection", side_effect=factory):
            first = threading.Thread(target=delete, name="delete-first", daemon=True)
            second = threading.Thread(target=insert, name="child-second", daemon=True)
            first.start()
            try:
                self.assertTrue(entered.wait(5))
                second.start()
                self.assertTrue(insert_connected.wait(5))
                self.assertFalse(insert_done.wait(0.2),
                                 "Child write bypassed finding deletion lock")
            finally:
                release.set()
                first.join(8)
                if second.ident is not None:
                    second.join(8)

        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertEqual(failures, [])
        self.assertTrue(outcome["deleted"])
        self.assertIsInstance(outcome["insert_error"], ValueError)
        self.assertIn("does not belong", str(outcome["insert_error"]))
        self.assertEqual(self.counts()["corrections"], 0)

    def test_sqlite_busy_is_fail_closed_and_retry_can_succeed(self):
        with closing(sqlite3.connect(self.path)) as blocking:
            blocking.execute("BEGIN IMMEDIATE")
            blocking.execute("UPDATE history SET status=status WHERE sl_no=1")
            with patch.object(db, "get_connection",
                              side_effect=lambda: self.connection(timeout=0.1)):
                with self.assertRaisesRegex(sqlite3.OperationalError, "locked"):
                    db.save_correction(1, 11, "verified", "", "", "fixture")
            self.assertEqual(self.counts()["corrections"], 0)
            blocking.rollback()
        with patch.object(db, "get_connection", side_effect=self.connection):
            self.assertIsInstance(
                db.save_correction(1, 11, "verified", "", "", "retry"), int)
        self.assertEqual(self.counts()["corrections"], 1)


if __name__ == "__main__":
    unittest.main()
