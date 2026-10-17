"""Transactional SQLite WAL snapshots for evaluation and distillation exports.

A second SQLite connection commits between SELECTs. Each export must read
one consistent version, with cleanup even if a query fails.
"""
from __future__ import annotations

from contextlib import closing
from pathlib import Path
import sqlite3
import tempfile
import unittest

from penx_app.storage.db_backend import SQLiteConnection
from penx_app.storage.evaluation_repository import (
    load_distillation_package, load_evaluation_package,
)
from penx_app.storage.schema_migrations import initialize_sqlite


class InterceptCursor:
    def __init__(self, real, callback):
        self.real = real
        self.callback = callback
        self.last_sql = ""

    def execute(self, sql, params=()):
        self.last_sql = sql
        self.real.execute(sql.replace("%s", "?"), params)
        return self

    def fetchone(self):
        record = self.real.fetchone()
        if "FROM history WHERE sl_no" in self.last_sql:
            self.callback()
        return record

    def fetchall(self):
        records = self.real.fetchall()
        if "FROM corrections c" in self.last_sql:
            self.callback()
        return records


class InterceptConnection(SQLiteConnection):
    def __init__(self, raw, callback):
        super().__init__(raw)
        self.callback = callback
        self.rollbacks = 0

    def cursor(self):
        return InterceptCursor(self._connection.cursor(), self.callback)

    def rollback(self):
        self.rollbacks += 1
        return self._connection.rollback()


class EvaluationSnapshotTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="penx-eval-snapshot-")
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / "fixture.sqlite"
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute("PRAGMA journal_mode=WAL").fetchone()[0], "wal")
            initialize_sqlite(db)
            db.execute(
                "INSERT INTO history (sl_no,target,scan_date,status) "
                "VALUES (1,'old.test','2026-10-17','active')")
            db.execute(
                "INSERT INTO summary (sl_no,raw_scan,ai_analysis,risk_level) "
                "VALUES (1,'old raw','old analysis','LOW')")
            db.execute(
                "INSERT INTO vulnerabilities (id,sl_no,vuln_name,severity) "
                "VALUES (5,1,'old finding','low')")
            db.execute(
                "INSERT INTO corrections (sl_no,vuln_id,status,reason,corrected_at) "
                "VALUES (1,5,'false_positive','old reason','2026-10-17')")
            db.execute(
                "INSERT INTO learned_rules (rule_text,source,created_at) "
                "VALUES ('old rule','synthetic','2026-10-17')")
            db.commit()

    def factory(self):
        return SQLiteConnection(sqlite3.connect(self.path, timeout=3))

    def callback_factory(self, callback, found):
        def factory():
            base = self.factory()
            wrapped = InterceptConnection(base._connection, callback)
            found.append(wrapped)
            return wrapped
        return factory

    def update(self, statements):
        with closing(sqlite3.connect(self.path, timeout=3)) as writer:
            for sql in statements:
                writer.execute(sql)
            writer.commit()

    def test_evaluation_export_is_consistent_during_writer_commit(self):
        invoked = []
        wrappers = []

        def write():
            if invoked:
                return
            invoked.append(True)
            self.update([
                "UPDATE history SET target='new.test' WHERE sl_no=1",
                "UPDATE summary SET raw_scan='new raw' WHERE sl_no=1",
                "UPDATE vulnerabilities SET vuln_name='new finding' WHERE id=5",
            ])

        first = load_evaluation_package(
            1, connection_factory=self.callback_factory(write, wrappers))
        self.assertEqual(invoked, [True])
        self.assertEqual(first["history"][1], "old.test")
        self.assertEqual(first["summary"][0], "old raw")
        self.assertEqual(first["vulns"][0].name, "old finding")
        self.assertEqual(wrappers[0].rollbacks, 1)
        second = load_evaluation_package(1, connection_factory=self.factory)
        self.assertEqual(second["history"][1], "new.test")
        self.assertEqual(second["summary"][0], "new raw")
        self.assertEqual(second["vulns"][0].name, "new finding")

    def test_distillation_export_is_consistent_during_writer_commit(self):
        invoked = []
        wrappers = []

        def write():
            if invoked:
                return
            invoked.append(True)
            self.update([
                "UPDATE corrections SET reason='new reason' WHERE sl_no=1",
                "UPDATE learned_rules SET rule_text='new rule'",
            ])

        first = load_distillation_package(
            connection_factory=self.callback_factory(write, wrappers))
        self.assertEqual(invoked, [True])
        self.assertEqual(first["corrections"][0][1], "old reason")
        self.assertEqual(first["rules"][0][1], "old rule")
        self.assertEqual(wrappers[0].rollbacks, 1)
        new = load_distillation_package(connection_factory=self.factory)
        self.assertEqual(new["corrections"][0][1], "new reason")
        self.assertEqual(new["rules"][0][1], "new rule")

    def test_evaluation_read_error_rolls_back_and_allows_next_write(self):
        wrappers = []

        def fail():
            raise RuntimeError("synthetic fetch failure")

        with self.assertRaisesRegex(RuntimeError, "synthetic fetch failure"):
            load_evaluation_package(
                1, connection_factory=self.callback_factory(fail, wrappers))
        self.assertEqual(wrappers[0].rollbacks, 1)
        self.update(["UPDATE summary SET raw_scan='available' WHERE sl_no=1"])
        fresh = load_evaluation_package(1, connection_factory=self.factory)
        self.assertEqual(fresh["summary"][0], "available")

    def test_distillation_read_error_rolls_back_and_allows_next_write(self):
        wrappers = []

        def fail():
            raise RuntimeError("synthetic fetch failure")

        with self.assertRaisesRegex(RuntimeError, "synthetic fetch failure"):
            load_distillation_package(
                connection_factory=self.callback_factory(fail, wrappers))
        self.assertEqual(wrappers[0].rollbacks, 1)
        self.update(["UPDATE learned_rules SET rule_text='available'"])
        fresh = load_distillation_package(connection_factory=self.factory)
        self.assertEqual(fresh["rules"][0][1], "available")


if __name__ == "__main__":
    unittest.main()
