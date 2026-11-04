"""PX-104 bounded offline session paging and redacted headless CLI."""
from __future__ import annotations

from contextlib import closing, redirect_stdout
from io import StringIO
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from penx_app.application.history_listing import main as listing_cli
from penx_app.bootstrap import main as bootstrap_main
from penx_app.storage.db_backend import SQLiteConnection
from penx_app.storage.schema_migrations import initialize_sqlite
from penx_app.storage.session_repository import HistoryPage, SessionRepository


class PagedHistoryTests(unittest.TestCase):
    def setUp(self):
        root = tempfile.TemporaryDirectory(prefix="px104-history-")
        self.addCleanup(root.cleanup)
        self.database = Path(root.name) / "history.sqlite3"
        with closing(sqlite3.connect(self.database)) as db:
            initialize_sqlite(db)
            entries = [
                (f"host-{i % 23}.example.test", "2026-11-04 10:00:00",
                 "active" if i % 7 else "pending")
                for i in range(1, 10_001)
            ]
            entries[7499] = ("täst-例子.example", "2026-11-01 22:59:59", "active")
            db.executemany(
                "INSERT INTO history (target, scan_date, status) VALUES (?, ?, ?)",
                entries)
            db.commit()

    def factory(self):
        raw = sqlite3.connect(self.database)
        return SQLiteConnection(raw)

    def page(self, **kwargs):
        return SessionRepository(self.factory).history_page(**kwargs)

    def test_10k_history_is_bounded_and_stably_ordered(self):
        first = self.page(limit=100)
        self.assertIsInstance(first, HistoryPage)
        self.assertEqual(len(first.entries), 100)
        self.assertTrue(all(x.status == "active" for x in first.entries))
        self.assertEqual(list(x.session_id for x in first.entries),
                         sorted((x.session_id for x in first.entries), reverse=True))
        self.assertIsNotNone(first.next_before_id)
        second = self.page(limit=100, before_id=first.next_before_id)
        self.assertEqual(len(second.entries), 100)
        self.assertLess(second.entries[0].session_id, first.entries[-1].session_id)
        self.assertFalse({x.session_id for x in first.entries}
                         & {x.session_id for x in second.entries})

    def test_target_and_date_filter_do_not_expand_or_inject(self):
        match = self.page(limit=10, target="täst-例子.example",
                          from_date="2026-11-01", until_date="2026-11-01")
        self.assertEqual([x.session_id for x in match.entries], [7500])
        self.assertIsNone(match.next_before_id)
        self.assertEqual(self.page(target="' OR 1=1 --").entries, ())
        self.assertEqual(self.page(target="no-such-host").entries, ())
        self.assertEqual(self.page(from_date="2026-11-05").entries, ())
        self.assertGreater(len(self.page(until_date="2026-11-04").entries), 0)

    def test_pending_is_explicit_and_absent_from_default(self):
        regular = self.page(limit=50)
        self.assertTrue(all(x.status == "active" for x in regular.entries))
        pending = self.page(limit=100, status="pending")
        self.assertEqual(len(pending.entries), 100)
        self.assertTrue(all(x.status == "pending" for x in pending.entries))

    def test_bad_filter_types_limits_dates_rejected_before_sql(self):
        invalid = [
            {"limit": 0}, {"limit": 101}, {"limit": True}, {"limit": "10"},
            {"before_id": 0}, {"before_id": -1}, {"before_id": True},
            {"status": "all"}, {"status": "active' OR TRUE --"},
            {"target": ""}, {"target": "line\ninvalid"}, {"target": "a" * 1025},
            {"from_date": "2026-13-31"}, {"until_date": "2026-02-30"},
            {"until_date": "2026-11-01", "from_date": "2026-11-02"},
            {"until_date": "9999-12-31"}, {"from_date": "20261104"},
        ]
        for params in invalid:
            with self.subTest(params=params), self.assertRaises(ValueError):
                self.page(**params)

    def test_read_paging_only_history_and_never_raw_artifacts(self):
        # A spy on execute records SQL and proves we never SELECT summary,
        # evaluations, raw scanner output or artifact files.
        queries = []
        class CapturingCursor:
            def __init__(self, inner):
                self.inner = inner
            def execute(self, sql, params=()):
                queries.append((sql, params))
                return self.inner.execute(sql, params)
            def fetchmany(self, n):
                return self.inner.fetchmany(n)
            def close(self):
                self.inner.close()
        class CapturingConnection:
            def __init__(self):
                self.inner = self_factory()
            def cursor(self):
                return CapturingCursor(self.inner.cursor())
            def close(self):
                self.inner.close()
        self_factory = self.factory
        page = SessionRepository(CapturingConnection).history_page(limit=5)
        self.assertEqual(len(page.entries), 5)
        self.assertEqual(len(queries), 1)
        self.assertIn("FROM history", queries[0][0])
        self.assertIn("LIMIT %s", queries[0][0])
        self.assertEqual(queries[0][1][-1], 6)
        self.assertNotIn("raw_scan", queries[0][0])

    def invoke(self, *argv):
        with redirect_stdout(StringIO()) as buffer:
            rc = listing_cli(["list", "--sqlite-db", str(self.database), *argv])
        return rc, json.loads(buffer.getvalue())

    def test_cli_redaction_and_explicit_opt_in(self):
        rc, result = self.invoke("--limit", "2", "--target", "täst-例子.example")
        self.assertEqual(rc, 0)
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["entries"][0]["target"], "[redacted]")
        self.assertTrue(result["target_redacted"])
        self.assertTrue(result["target_filter_applied"])
        self.assertNotIn("täst", json.dumps(result, ensure_ascii=False))
        rc, visible = self.invoke("--show-target", "--target", "täst-例子.example")
        self.assertEqual(rc, 0)
        self.assertEqual(visible["entries"][0]["target"], "täst-例子.example")
        self.assertFalse(visible["target_redacted"])
        self.assertFalse(visible["has_more"])

    def test_cli_cursor_bounded_and_no_implicit_database_creation(self):
        rc, first = self.invoke("--limit", "3")
        self.assertEqual(rc, 0)
        self.assertEqual(first["count"], 3)
        self.assertTrue(first["has_more"])
        rc, second = self.invoke("--limit", "3",
                                 "--before-id", str(first["next_before_id"]))
        self.assertEqual(rc, 0)
        self.assertLess(second["entries"][0]["session_id"],
                        first["entries"][-1]["session_id"])
        absent = self.database.with_name("missing.sqlite")
        with redirect_stdout(StringIO()) as buffer:
            self.assertEqual(listing_cli(["list", "--sqlite-db", str(absent)]), 2)
        self.assertFalse(absent.exists())
        self.assertEqual(json.loads(buffer.getvalue())["status"], "unavailable")
        self.assertNotIn(str(absent), buffer.getvalue())

    def test_symlink_refused_and_file_unchanged(self):
        alias = self.database.with_name("alias.sqlite")
        try:
            alias.symlink_to(self.database)
        except (NotImplementedError, OSError):
            self.skipTest("Symlinks unavailable")
        with redirect_stdout(StringIO()) as buffer:
            self.assertEqual(listing_cli(["list", "--sqlite-db", str(alias)]), 2)
        self.assertEqual(json.loads(buffer.getvalue())["status"], "unavailable")

    def test_cli_does_not_access_network_or_execute_process(self):
        with (patch("socket.create_connection",
                    side_effect=AssertionError("unexpected network")),
              patch("subprocess.run",
                    side_effect=AssertionError("unexpected process"))):
            rc, info = self.invoke("--limit", "4")
        self.assertEqual(rc, 0)
        self.assertEqual(info["count"], 4)

    def test_bootstrap_dispatches_no_interactive_prompt(self):
        with patch("sys.argv", ["penx.py", "history", "list",
                                "--sqlite-db", str(self.database), "--limit", "2"]), \
             redirect_stdout(StringIO()) as buffer:
            self.assertEqual(bootstrap_main(), 0)
        info = json.loads(buffer.getvalue())
        self.assertEqual(info["count"], 2)
        self.assertTrue(info["target_redacted"])


if __name__ == "__main__":
    unittest.main()
