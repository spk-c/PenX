"""Consistent session reads when a writer commits mid-snapshot (SQLite WAL).

Each test uses a disposable SQLite file; there are no live scanners or accounts.
"""
from __future__ import annotations

from contextlib import closing
from pathlib import Path
import sqlite3
import tempfile
import unittest

from penx_app.storage.db_backend import SQLiteConnection
from penx_app.storage.schema_migrations import initialize_sqlite
from penx_app.storage.session_repository import SessionRepository


class AfterHistoryCursor:
    def __init__(self, original, callback):
        self.original = original
        self.callback = callback
        self.query = ""

    def execute(self, query, params=()):
        self.query = query
        self.original.execute(query.replace("%s", "?"), params)
        return self

    def fetchone(self):
        row = self.original.fetchone()
        if "FROM history WHERE sl_no" in self.query:
            self.callback()
        return row

    def fetchall(self):
        return self.original.fetchall()


class HookedConnection(SQLiteConnection):
    def __init__(self, connection, after_history):
        super().__init__(connection)
        self.after_history = after_history
        self.rollbacks = 0

    def cursor(self):
        return AfterHistoryCursor(self._connection.cursor(), self.after_history)

    def rollback(self):
        self.rollbacks += 1
        return self._connection.rollback()


class ConsistentSnapshotTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="penx-snapshot-wal-")
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / "data.sqlite"
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute("PRAGMA journal_mode=WAL").fetchone()[0], "wal")
            initialize_sqlite(db)
            db.execute(
                "INSERT INTO history(sl_no,target,scan_date,status) VALUES(1,'old.test','2026-10-17','active')"
            )
            db.execute(
                "INSERT INTO vulnerabilities(sl_no,vuln_name,severity) VALUES(1,'Old finding','low')"
            )
            db.execute(
                "INSERT INTO summary(sl_no,raw_scan,ai_analysis,risk_level) VALUES(1,'old raw','old assessment','LOW')"
            )
            db.commit()

    def factory(self):
        db = sqlite3.connect(self.path, timeout=3)
        db.execute("PRAGMA busy_timeout=3000")
        return SQLiteConnection(db)

    def test_concurrent_writer_cannot_mix_old_and_new_session_tables(self):
        calls = []
        wrappers = []

        def commit_change():
            if calls:
                return
            calls.append("writer")
            # WAL allows this writer to commit while a reader pins an
            # earlier snapshot; a nontransactional reader sees mixed data.
            with closing(sqlite3.connect(self.path, timeout=3)) as writer:
                writer.execute("UPDATE history SET target='new.test' WHERE sl_no=1")
                writer.execute("UPDATE vulnerabilities SET vuln_name='New finding' WHERE sl_no=1")
                writer.execute("UPDATE summary SET raw_scan='new raw' WHERE sl_no=1")
                writer.commit()

        def instrumented_factory():
            original = self.factory()
            wrapper = HookedConnection(original._connection, commit_change)
            wrappers.append(wrapper)
            return wrapper

        old = SessionRepository(instrumented_factory).snapshot(1)
        self.assertEqual(calls, ["writer"])
        self.assertEqual(old.history.target, "old.test")
        self.assertEqual(old.findings[0].name, "Old finding")
        self.assertEqual(old.summary.raw_scan, "old raw")
        self.assertEqual(wrappers[0].rollbacks, 1)

        # The next request must see the newly committed, consistent version.
        fresh = SessionRepository(self.factory).snapshot(1)
        self.assertEqual(fresh.history.target, "new.test")
        self.assertEqual(fresh.findings[0].name, "New finding")
        self.assertEqual(fresh.summary.raw_scan, "new raw")

    def test_read_transaction_releases_snapshot_after_query_failure(self):
        wrappers = []

        def raise_during_snapshot():
            raise RuntimeError("synthetic fetch failure")

        def factory():
            original = self.factory()
            wrapper = HookedConnection(original._connection, raise_during_snapshot)
            wrappers.append(wrapper)
            return wrapper

        with self.assertRaisesRegex(RuntimeError, "synthetic fetch failure"):
            SessionRepository(factory).snapshot(1)
        self.assertEqual(wrappers[0].rollbacks, 1)
        with closing(sqlite3.connect(self.path, timeout=3)) as writer:
            writer.execute("UPDATE history SET target='still writable' WHERE sl_no=1")
            writer.commit()
        self.assertEqual(SessionRepository(self.factory).snapshot(1).history.target,
                         "still writable")


if __name__ == "__main__":
    unittest.main()
