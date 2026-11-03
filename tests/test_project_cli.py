"""Offline end-to-end tests for the `penx project` headless CLI (PX-101).

Drives ProjectService.main against a temp SQLite database, asserting both the
printed output and the documented exit codes (0 authorized/ok, 1 not
authorized, 2 usage/scope/storage error). No network, no subprocess.
"""
import contextlib
import io
import sqlite3
import tempfile
import unittest
from contextlib import closing

from penx_app.application.project_service import main
from penx_app.storage.db_backend import SQLiteConnection
from penx_app.storage.schema_migrations import initialize_sqlite


def _run(argv, factory):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        code = main(argv, connection_factory=factory)
    return code, buf.getvalue()


class ProjectCliTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.db_path = self._tmp.name + '\\penx_cli_test.db'
        with closing(sqlite3.connect(self.db_path)) as conn:
            initialize_sqlite(conn)
        self.factory = lambda: SQLiteConnection(sqlite3.connect(self.db_path))

    def _create(self, name='proj1'):
        code, out = _run(['create', name], self.factory)
        self.assertEqual(code, 0, out)
        self.assertIn('Created project: ' + name, out)

    def test_create(self):
        self._create()

    def test_create_duplicate_rejected(self):
        self._create()
        code, out = _run(['create', 'proj1'], self.factory)
        self.assertEqual(code, 2, out)
        self.assertIn('already exists', out)

    def test_create_blank_name_rejected(self):
        code, out = _run(['create', '   '], self.factory)
        self.assertEqual(code, 2, out)

    def test_add_approved(self):
        self._create()
        code, out = _run(['add', 'proj1', '--target', 'example.test'],
                        self.factory)
        self.assertEqual(code, 0, out)
        self.assertIn('approved asset', out)

    def test_add_unknown_project_rejected(self):
        code, out = _run(['add', 'nope', '--target', 'example.test'],
                        self.factory)
        self.assertEqual(code, 2, out)
        self.assertIn('Unknown project', out)

    def test_add_duplicate_rejected(self):
        self._create()
        self._add_ok('example.test')
        code, out = _run(['add', 'proj1', '--target', 'example.test'],
                        self.factory)
        self.assertEqual(code, 2, out)
        self.assertIn('already recorded', out)

    def test_add_invalid_target_rejected(self):
        self._create()
        code, out = _run(['add', 'proj1', '--target', 'a b'], self.factory)
        self.assertEqual(code, 2, out)

    def test_add_candidate_not_authorized(self):
        self._create()
        code, out = _run(['add', 'proj1', '--target', 'sub.example.test',
                         '--as-candidate'], self.factory)
        self.assertEqual(code, 0, out)
        self.assertIn('candidate', out)
        code, out = _run(['check', 'proj1', '--target', 'sub.example.test'],
                        self.factory)
        self.assertEqual(code, 1, out)
        self.assertIn('not authorized', out)

    def test_list_projects(self):
        self._create('alpha')
        self._create('beta')
        code, out = _run(['list'], self.factory)
        self.assertEqual(code, 0, out)
        self.assertIn('alpha', out)
        self.assertIn('beta', out)

    def test_list_assets(self):
        self._create()
        self._add_ok('example.test')
        code, out = _run(['list', 'proj1'], self.factory)
        self.assertEqual(code, 0, out)
        self.assertIn('example.test', out)

    def test_list_assets_unknown_project(self):
        code, out = _run(['list', 'nope'], self.factory)
        self.assertEqual(code, 2, out)

    def test_check_authorized(self):
        self._create()
        self._add_ok('example.test')
        code, out = _run(['check', 'proj1', '--target', 'example.test'],
                        self.factory)
        self.assertEqual(code, 0, out)
        self.assertIn('authorized', out)
        self.assertNotIn('not authorized', out)

    def test_check_not_authorized(self):
        self._create()
        self._add_ok('example.test')
        code, out = _run(['check', 'proj1', '--target', 'other.test'],
                        self.factory)
        self.assertEqual(code, 1, out)
        self.assertIn('not authorized', out)

    def test_check_unknown_project(self):
        code, out = _run(['check', 'nope', '--target', 'example.test'],
                        self.factory)
        self.assertEqual(code, 2, out)

    def test_check_host_level_covers_port(self):
        self._create()
        self._add_ok('example.test')
        code, out = _run(['check', 'proj1', '--target', 'example.test:443'],
                        self.factory)
        self.assertEqual(code, 0, out)
        self.assertIn('authorized', out)

    def test_preview(self):
        self._create()
        self._add_ok('example.test')
        code, out = _run(['preview', 'proj1'], self.factory)
        self.assertEqual(code, 0, out)
        self.assertIn('example.test', out)

    def test_preview_cidr_bounded(self):
        self._create()
        code, out = _run(['add', 'proj1', '--target', '192.168.0.0/30'],
                        self.factory)
        self.assertEqual(code, 0, out)
        code, out = _run(['preview', 'proj1'], self.factory)
        self.assertEqual(code, 0, out)
        self.assertIn('CIDR 192.168.0.0/30', out)
        self.assertIn('4 address(es)', out)

    def test_usage_error_unknown_action(self):
        code, _ = _run(['bogus'], self.factory)
        self.assertEqual(code, 2)

    def _add_ok(self, target):
        code, out = _run(['add', 'proj1', '--target', target], self.factory)
        self.assertEqual(code, 0, out)


if __name__ == '__main__':
    unittest.main()
