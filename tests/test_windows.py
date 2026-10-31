"""Offline port regression tests. Uses an isolated SQLite database.

Run: python offline_tests.py (after installing requirements).
"""
import json
import os
import tempfile
import threading
import unittest
from unittest.mock import patch
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

_TMP = tempfile.TemporaryDirectory(prefix='penx_test_')
os.environ['PENX_DB_ENGINE'] = 'sqlite'
os.environ['PENX_DB_PATH'] = str(Path(_TMP.name) / 'test.db')

from penx_app.config import DB_PATH
from penx_app.storage import db
from penx_app.storage.db_evals import save_evaluation, get_evaluations, save_learned_rule
from penx_app.storage.db_training import export_training_data
from penx_app.reporting.export import fetch_session, export_html, export_pdf
from penx_app.analysis.llm import load_correction_rules
from penx_app.scanners.tools import (_host, run_tool_by_command, run_curl_headers, run_whatweb,
                   run_nikto, run_dig)


class Handler(BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.send_response(200)
        self.send_header('X-Powered-By', 'TestServer/1.0')
        self.end_headers()

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(b'<html><meta name="generator" content="UnitTest CMS">Hi</html>')

    def log_message(self, *args):
        pass


class PortTests(unittest.TestCase):
    def setUp(self):
        # This suite verifies missing scanners and the Python HTTP fallback.
        # Never depend on locally installed or inaccessible vendor directories.
        for name in ('NIKTO_PATH', 'WHATWEB_PATH'):
            patcher = patch('penx_app.scanners.tools.' + name, '')
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_program_version_cli(self):
        import subprocess
        import sys
        result = subprocess.run([sys.executable, str(Path(__file__).resolve().parent.parent / 'penx.py'), '--version'],
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('PenX Windows', result.stdout)

    def test_path_for_source_mode(self):
        from penx_app.app_paths import APP_ROOT
        self.assertEqual(APP_ROOT, Path(__file__).resolve().parent.parent)

    def test_sqlite_crud_exports_and_training(self):
        self.assertTrue(Path(DB_PATH).parent.exists())
        sl = db.create_session('http://localhost:4444')
        self.assertGreater(sl, 0)
        vuln = db.save_vulnerability(sl, 'Example issue', 'low', '443', 'HTTPS', 'Test description', 'possible')
        db.save_fix(sl, vuln, 'Patch test service')
        db.save_exploit(sl, 'Simulated event', 'none', 'no payload', 'not run', 'No action')
        db.save_summary(sl, 'test raw scan', 'test AI analysis', 'LOW', model_name='dummy')
        self.assertEqual(db.get_session(sl)['vulns'][0][5], '443')
        db.save_correction(sl, vuln, 'corrected', 'Example issue', 'Corrected issue', 'low impact')
        ev = save_evaluation(sl, vuln, 'unit-test', 'dummy evidence', 'valid', 'high', True,
                             True, True, False, 'No action')
        self.assertGreater(ev, 0)
        self.assertEqual(len(get_evaluations(sl)), 1)
        rid = save_learned_rule('Only claim findings supported by scan output', 'test')
        self.assertGreater(rid, 0)
        self.assertIn('Only claim findings', load_correction_rules())
        db.edit_vulnerability(vuln, 'service', 'HTTPS unit test', sl_no=sl)
        self.assertEqual(db.get_vulnerabilities(sl)[0][6], 'HTTPS unit test')
        with tempfile.TemporaryDirectory() as reports:
            data = fetch_session(sl)
            self.assertEqual(data['summary'][5], 'dummy')
            h = export_html(data, reports)
            p = export_pdf(data, reports)
            self.assertTrue(Path(h).is_file())
            self.assertTrue(Path(p).is_file())
            self.assertGreater(Path(p).stat().st_size, 500)
            training = export_training_data(reports)
            self.assertTrue(Path(training).is_file())
            records = [json.loads(line) for line in Path(training).read_text(encoding='utf8').splitlines()]
            self.assertTrue(records)
            # Scope to this test's own session: with other test files sharing
            # the same in-process DB, records[0] may belong to a foreign session.
            own = next(r for r in records if r['metadata']['sl_no'] == sl)
            self.assertEqual(own['metadata']['target'], 'http://localhost:4444')
            self.assertIn('PORT: 443', own['messages'][1]['content'])
        db.delete_full_session(sl)
        self.assertIsNone(db.get_session(sl)['history'])

    def test_normalize_and_allowlist(self):
        self.assertEqual(_host('http://localhost:4040/foo'), 'localhost')
        self.assertEqual(_host('192.168.1.0/24'), '192.168.1.0/24')
        for target in ('-sV', 'a b', 'http://', 'bad..site'):
            with self.assertRaises(ValueError):
                _host(target)
        self.assertIn('not permitted', run_tool_by_command('powershell -command test', authorized_target='localhost'))
        self.assertIn('exactly one target', run_tool_by_command('nmap -sV', authorized_target='localhost'))

    def test_windows_http_fallback(self):
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f'http://127.0.0.1:{server.server_port}'
            head = run_curl_headers(url)
            self.assertIn('X-Powered-By: TestServer/1.0', head)
            fp = run_whatweb(url)
            self.assertIn('UnitTest CMS', fp)
            self.assertIn('NOT an actual WhatWeb scan', fp)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_optional_tool_warning(self):
        msg = run_nikto('localhost')
        self.assertTrue(('optional' in msg) or ('Nikto' in msg))
        self.assertIn('not a subnet', run_dig('192.168.1.0/24'))


if __name__ == '__main__':
    try:
        result = unittest.main(verbosity=2, exit=False).result
    finally:
        _TMP.cleanup()
    raise SystemExit(0 if result.wasSuccessful() else 1)
