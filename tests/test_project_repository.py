"""Offline tests for the project scope registry persistence (PX-101).

Uses a fresh temp SQLite database upgraded through initialize_sqlite so the
v4 project tables are present. Verifies create/read/list, the unique
(canonical, kind) index, asset counting, and deletion. No network, no
subprocess.
"""
import sqlite3
import tempfile
import unittest
from contextlib import closing
from datetime import datetime, timezone

from penx_app.storage.db_backend import SQLiteConnection
from penx_app.storage.project_repository import AssetRow, ProjectRepository
from penx_app.storage.schema_migrations import SCHEMA_VERSION, initialize_sqlite


class ProjectRepositoryTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.db_path = self._tmp.name + '\\penx_test.db'
        with closing(sqlite3.connect(self.db_path)) as conn:
            initialize_sqlite(conn)
        self.repo = ProjectRepository(
            connection_factory=lambda: SQLiteConnection(
                sqlite3.connect(self.db_path)))

    def _add(self, project_id, raw, canonical, kind='host', status='approved'):
        row = AssetRow(0, project_id, raw, canonical, kind, status,
                       datetime(2026, 1, 1, tzinfo=timezone.utc).isoformat(),
                       None, None, None, '')
        return self.repo.add_asset(row)

    def test_fresh_tables_present(self):
        with closing(sqlite3.connect(self.db_path)) as conn:
            self.assertEqual(conn.execute('PRAGMA user_version').fetchone()[0],
                             SCHEMA_VERSION)
            for table in ('projects', 'project_assets'):
                info = conn.execute(f'PRAGMA table_info({table})').fetchall()
            self.assertTrue(info)

    def test_create_project(self):
        pid = self.repo.create_project('p1', '2026-01-01T00:00:00+00:00')
        self.assertIsInstance(pid, int)
        project = self.repo.get_project('p1')
        self.assertIsNotNone(project)
        self.assertEqual(project.name, 'p1')
        self.assertEqual(project.id, pid)

    def test_create_duplicate_name_rejected(self):
        self.repo.create_project('p1', '2026-01-01T00:00:00+00:00')
        with self.assertRaises(sqlite3.IntegrityError):
            self.repo.create_project('p1', '2026-01-01T00:00:00+00:00')

    def test_get_missing_project_none(self):
        self.assertIsNone(self.repo.get_project('nope'))

    def test_list_projects_ordered(self):
        self.repo.create_project('a', '2026-01-01T00:00:00+00:00')
        self.repo.create_project('b', '2026-01-01T00:00:00+00:00')
        names = [p.name for p in self.repo.list_projects()]
        self.assertEqual(names, ['a', 'b'])

    def test_add_and_list_asset(self):
        pid = self.repo.create_project('p1', '2026-01-01T00:00:00+00:00')
        asset_id = self._add(pid, 'example.test', 'example.test')
        self.assertIsInstance(asset_id, int)
        rows = self.repo.list_assets(pid)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].canonical, 'example.test')
        self.assertEqual(rows[0].kind, 'host')
        self.assertEqual(rows[0].status, 'approved')

    def test_duplicate_canonical_kind_rejected(self):
        pid = self.repo.create_project('p1', '2026-01-01T00:00:00+00:00')
        self._add(pid, 'example.test', 'example.test', kind='host')
        with self.assertRaises(sqlite3.IntegrityError):
            self._add(pid, 'EXAMPLE.test', 'example.test', kind='host')

    def test_same_canonical_different_kind_allowed(self):
        pid = self.repo.create_project('p1', '2026-01-01T00:00:00+00:00')
        self._add(pid, '192.168.0.0/30', '192.168.0.0/30', kind='cidr')
        self._add(pid, 'example.test', 'example.test', kind='host')
        self.assertEqual(self.repo.asset_count(pid), 2)

    def test_asset_count(self):
        pid = self.repo.create_project('p1', '2026-01-01T00:00:00+00:00')
        self.assertEqual(self.repo.asset_count(pid), 0)
        self._add(pid, 'example.test', 'example.test')
        self._add(pid, 'other.test', 'other.test')
        self.assertEqual(self.repo.asset_count(pid), 2)

    def test_candidate_promotion_is_atomic_and_one_time(self):
        pid = self.repo.create_project('p1', '2026-01-01T00:00:00+00:00')
        self._add(pid, 'example.test', 'example.test', status='candidate')
        original = self.repo.list_assets(pid)[0].approved_at
        timestamp = '2026-11-04T12:00:00+00:00'
        self.assertFalse(self.repo.approve_candidate(
            pid, 'other.test', 'host',
            approved_at=timestamp, expected_candidate_at=original))
        self.assertFalse(self.repo.approve_candidate(
            pid, 'example.test', 'host',
            approved_at=timestamp, expected_candidate_at='wrong-timestamp'))
        self.assertTrue(self.repo.approve_candidate(
            pid, 'example.test', 'host',
            approved_at=timestamp, expected_candidate_at=original))
        self.assertFalse(self.repo.approve_candidate(
            pid, 'example.test', 'host',
            approved_at=timestamp, expected_candidate_at=original))
        after = self.repo.list_assets(pid)[0]
        self.assertEqual((after.status, after.approved_at), ('approved', timestamp))

    def test_revocation_demotes_without_deletion_or_target_expansion(self):
        pid = self.repo.create_project('p1', '2026-01-01T00:00:00+00:00')
        self._add(pid, 'example.test:443', 'example.test:443')
        self._add(pid, 'example.test:8443', 'example.test:8443')
        self.assertFalse(self.repo.revoke_approval(pid, 'example.test', 'host'))
        self.assertTrue(self.repo.revoke_approval(pid, 'example.test:443', 'host'))
        self.assertFalse(self.repo.revoke_approval(pid, 'example.test:443', 'host'))
        rows = self.repo.list_assets(pid)
        self.assertEqual([(r.canonical, r.status) for r in rows], [
            ('example.test:443', 'candidate'),
            ('example.test:8443', 'approved')])
        self.assertEqual(self.repo.asset_count(pid), 2)

    def test_delete_asset(self):
        pid = self.repo.create_project('p1', '2026-01-01T00:00:00+00:00')
        self._add(pid, 'example.test', 'example.test')
        self.assertTrue(self.repo.delete_asset(pid, 'example.test', 'host'))
        self.assertEqual(self.repo.asset_count(pid), 0)
        self.assertFalse(self.repo.delete_asset(pid, 'example.test', 'host'))


class LegacyMigrationTests(unittest.TestCase):
    """A pre-PX-101 database (schema v3) must converge to v4 additively."""

    def test_v3_database_converges_to_v4(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = tmp.name + '\\legacy.db'
        from penx_app.storage.schema_migrations import SCHEMA
        with closing(sqlite3.connect(path)) as conn:
            conn.executescript('BEGIN IMMEDIATE;\n' + SCHEMA + 'COMMIT;')
            for table, column, declaration in (
                    ('vulnerabilities', 'confidence', "TEXT DEFAULT 'possible'"),
                    ('summary', 'model_name', "TEXT DEFAULT ''"),
                    ('history', 'status', "TEXT DEFAULT 'active'"),
                    ('summary', 'scan_metadata', "TEXT DEFAULT ''")):
                existing = {r[1] for r in conn.execute(
                    f'PRAGMA table_info({table})')}
                if column not in existing:
                    conn.execute(
                        f'ALTER TABLE {table} ADD COLUMN {column} {declaration}')
            conn.execute('PRAGMA user_version=3')
            conn.commit()
        with closing(sqlite3.connect(path)) as conn:
            initialize_sqlite(conn)
            self.assertEqual(
                conn.execute('PRAGMA user_version').fetchone()[0], SCHEMA_VERSION)
            tables = {r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
            self.assertIn('projects', tables)
            self.assertIn('project_assets', tables)
        # Re-opening an already-v4 database is a no-op that keeps the tables.
        with closing(sqlite3.connect(path)) as conn:
            initialize_sqlite(conn)
            self.assertEqual(
                conn.execute('PRAGMA user_version').fetchone()[0], SCHEMA_VERSION)


if __name__ == '__main__':
    unittest.main()
