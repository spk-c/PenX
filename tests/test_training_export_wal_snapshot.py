"""Training JSONL exports use one SQLite WAL read snapshot.

All fixtures are disposable; a separate SQLite connection commits real
changes between SELECT statements. No customer data or network access.
"""
from __future__ import annotations

from contextlib import closing
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from penx_app.storage import db_training
from penx_app.storage.db_backend import SQLiteConnection
from penx_app.storage.schema_migrations import initialize_sqlite


class HookedCursor:
    def __init__(self, underlying, callback, trigger):
        self.underlying = underlying
        self.callback = callback
        self.trigger = trigger
        self.statement = ""

    def execute(self, statement, params=()):
        self.statement = statement
        self.underlying.execute(statement, params)
        return self

    def fetchone(self):
        row = self.underlying.fetchone()
        if self.trigger == "summary" and "FROM summary WHERE sl_no" in self.statement:
            self.callback()
        return row

    def fetchall(self):
        rows = self.underlying.fetchall()
        if self.trigger == "sessions" and "SELECT DISTINCT c.sl_no" in self.statement:
            self.callback()
        return rows

    def __getattr__(self, name):
        return getattr(self.underlying, name)


class HookedConnection(SQLiteConnection):
    def __init__(self, connection, callback, trigger):
        super().__init__(connection)
        self.callback = callback
        self.trigger = trigger
        self.rollbacks = 0
        self.closed = False

    def cursor(self):
        return HookedCursor(super().cursor(), self.callback, self.trigger)

    def rollback(self):
        self.rollbacks += 1
        return super().rollback()

    def close(self):
        self.closed = True
        return super().close()


class TrainingExportSnapshotTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="penx-training-wal-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.path = self.root / "history.sqlite"
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute("PRAGMA journal_mode=WAL").fetchone()[0], "wal")
            initialize_sqlite(db)
            db.execute(
                "INSERT INTO history(sl_no,target,scan_date,status) "
                "VALUES(1,'old.test','today','active')"
            )
            db.execute(
                "INSERT INTO history(sl_no,target,scan_date,status) "
                "VALUES(2,'second.test','today','active')"
            )
            db.execute(
                "INSERT INTO summary(sl_no,raw_scan,ai_analysis,risk_level) "
                "VALUES(1,'old raw','old analysis','LOW')"
            )
            db.execute(
                "INSERT INTO summary(sl_no,raw_scan,ai_analysis,risk_level) "
                "VALUES(2,'second raw','second analysis','LOW')"
            )
            db.execute(
                "INSERT INTO vulnerabilities(id,sl_no,vuln_name,severity,confidence) "
                "VALUES(11,1,'Old verified finding','low','confirmed')"
            )
            db.execute(
                "INSERT INTO vulnerabilities(id,sl_no,vuln_name,severity,confidence) "
                "VALUES(22,2,'Second verified finding','medium','possible')"
            )
            db.execute(
                "INSERT INTO corrections(sl_no,vuln_id,status,reason,corrected_at) "
                "VALUES(1,11,'verified','old reason','today')"
            )
            db.commit()

    def raw_factory(self):
        return SQLiteConnection(sqlite3.connect(self.path, timeout=3))

    def hooked_factory(self, callback, trigger, out):
        def factory():
            base = self.raw_factory()
            connection = HookedConnection(base._connection, callback, trigger)
            out.append(connection)
            return connection
        return factory

    def commit(self, sqls):
        with closing(sqlite3.connect(self.path, timeout=3)) as writer:
            for statement in sqls:
                writer.execute(statement)
            writer.commit()

    def export(self, *, factory=None):
        with patch.object(db_training, "get_connection",
                          side_effect=factory or self.raw_factory):
            output = db_training.export_training_data(str(self.root))
        self.assertTrue(output, "Expected an individually reviewed finding")
        return [json.loads(line) for line in
                Path(output).read_text(encoding="utf-8").splitlines()]

    def test_parallel_commit_cannot_mix_raw_scan_and_correction_labels(self):
        invoked = []
        holders = []

        def update():
            if invoked:
                return
            invoked.append(True)
            self.commit([
                "UPDATE history SET target='new.test' WHERE sl_no=1",
                "UPDATE summary SET raw_scan='new raw' WHERE sl_no=1",
                "UPDATE vulnerabilities SET vuln_name='New verified finding' WHERE id=11",
                "UPDATE corrections SET status='corrected', "
                "corrected_text='new corrected detail', reason='new reason' "
                "WHERE sl_no=1",
            ])

        old = self.export(
            factory=self.hooked_factory(update, "summary", holders))
        self.assertEqual(invoked, [True])
        self.assertEqual(len(old), 1)
        original = old[0]
        self.assertIn("TARGET: old.test", original["messages"][0]["content"])
        self.assertIn("RECON DATA:\nold raw", original["messages"][0]["content"])
        self.assertIn("VULN: Old verified finding", original["messages"][1]["content"])
        self.assertNotIn("New verified finding", original["messages"][1]["content"])
        self.assertEqual(original["metadata"]["corrections_applied"], 1)
        self.assertEqual(holders[0].rollbacks, 1)
        self.assertTrue(holders[0].closed)

        fresh = self.export()
        self.assertEqual(len(fresh), 1)
        self.assertIn("TARGET: new.test", fresh[0]["messages"][0]["content"])
        self.assertIn("RECON DATA:\nnew raw", fresh[0]["messages"][0]["content"])
        self.assertIn("VULN: New verified finding", fresh[0]["messages"][1]["content"])
        self.assertIn("DESC: new corrected detail", fresh[0]["messages"][1]["content"])

    def test_newly_reviewed_session_is_only_visible_on_next_export(self):
        invoked = []
        holders = []

        def approve_second():
            if invoked:
                return
            invoked.append(True)
            self.commit([
                "INSERT INTO corrections(sl_no,vuln_id,status,reason,corrected_at) "
                "VALUES(2,22,'verified','reviewed later','today')"
            ])

        first = self.export(
            factory=self.hooked_factory(approve_second, "sessions", holders))
        self.assertEqual(invoked, [True])
        self.assertEqual([r["metadata"]["sl_no"] for r in first], [1])
        self.assertEqual(holders[0].rollbacks, 1)
        later = self.export()
        self.assertEqual([r["metadata"]["sl_no"] for r in later], [1, 2])

    def test_read_failure_releases_snapshot_before_writer_retries(self):
        holders = []

        def broken():
            raise RuntimeError("synthetic read failure")

        with patch.object(db_training, "get_connection",
                          side_effect=self.hooked_factory(broken, "summary", holders)):
            with self.assertRaisesRegex(RuntimeError, "synthetic read failure"):
                db_training.export_training_data(str(self.root))
        self.assertEqual(holders[0].rollbacks, 1)
        self.assertTrue(holders[0].closed)
        self.commit(["UPDATE summary SET raw_scan='writable again' WHERE sl_no=1"])
        self.assertIn("writable again", self.export()[0]["messages"][0]["content"])

    def test_file_publication_happens_after_database_connection_closes(self):
        holders = []
        from penx_app.file_output import publish_unique
        def assert_closed(*args, **kwargs):
            self.assertTrue(holders[0].closed)
            return publish_unique(*args, **kwargs)
        with patch.object(db_training, "get_connection",
                          side_effect=self.hooked_factory(lambda: None, "summary", holders)), \
             patch.object(db_training, "publish_unique", side_effect=assert_closed):
            path = db_training.export_training_data(str(self.root))
        self.assertTrue(Path(path).is_file())
        self.assertEqual(holders[0].rollbacks, 1)


if __name__ == "__main__":
    unittest.main()
