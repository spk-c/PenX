"""PX-003: synthetic bytes through real, bounded local child processes."""
from contextlib import ExitStack, redirect_stdout
import hashlib
from io import StringIO
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from penx_app.application.headless_scan import scan_report
from penx_app.application.scan_profiles import build_custom_plan
from penx_app.application.scanner_execution import run_selected_structured
from penx_app.domain.scan_models import ScanRequest
from penx_app.reporting.machine_reports import sarif_from_report
from penx_app.scanners import process_runner

PACK = ROOT / 'tests/fixtures/scanner_corpus/process_bytes_v1.json'
# Only these trusted instructions execute; fixture bytes remain inert files.
CHILD = ('from pathlib import Path;import sys;'
         'sys.stdout.buffer.write(Path(sys.argv[1]).read_bytes());sys.stdout.buffer.flush();'
         'sys.stderr.buffer.write(Path(sys.argv[2]).read_bytes());sys.stderr.buffer.flush()')


class ProcessGoldenCorpusTests(unittest.TestCase):
    def setUp(self):
        self.pack = json.loads(PACK.read_text(encoding='utf-8'))
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.guards = [self.stack.enter_context(patch(name, side_effect=AssertionError('No network')))
                       for name in ('socket.socket.connect', 'socket.socket.connect_ex',
                                    'socket.socket.sendto', 'socket.getaddrinfo')]

    def tearDown(self):
        for guard in self.guards:
            guard.assert_not_called()

    def payload(self, description):
        count = description.get('repeat', 1)
        unit = bytes.fromhex(description['hex'])
        suffix = bytes.fromhex(description.get('suffix_hex', ''))
        self.assertIs(type(count), int)
        self.assertGreaterEqual(count, 0)
        self.assertLessEqual(len(unit) * count + len(suffix), process_runner.MAX_CAPTURE_BYTES + 8192)
        data = unit * count + suffix
        self.assertEqual(hashlib.sha256(data).hexdigest(), description['sha256'])
        return data

    def test_byte_pack_through_both_process_modes_and_exports(self):
        self.assertEqual(self.pack['schema'], 'penx-process-corpus-v1')
        self.assertEqual(self.pack['provenance']['kind'], 'hand-authored-synthetic')
        cases = self.pack['cases']
        self.assertEqual(len({case['id'] for case in cases}), len(cases))
        for case in cases:
            stdout, stderr = self.payload(case['stdout']), self.payload(case['stderr'])
            expected = case['expected']
            projections = []
            with tempfile.TemporaryDirectory(prefix='penx-byte-corpus-') as folder:
                out_path, err_path = Path(folder) / 'stdout.bin', Path(folder) / 'stderr.bin'
                out_path.write_bytes(stdout)
                err_path.write_bytes(stderr)
                for live in (False, True):
                    terminal = StringIO()
                    with self.subTest(case=case['id'], live=live), \
                         patch.dict(os.environ, {'PENX_LIVE_OUTPUT': str(int(live))}), \
                         patch.object(process_runner, '_CHUNK_BYTES', case.get('chunk_bytes', 8192)), \
                         redirect_stdout(terminal):
                        result = process_runner.run_tool(
                            [sys.executable, '-c', CHILD, str(out_path), str(err_path)], timeout=15)
                        self.assertEqual(result.status, expected['status'])
                        self.assertEqual(result.evidence, expected['evidence'])
                        self.assertEqual(result.exit_code, 0)
                        if 'text' in expected:
                            self.assertEqual(str(result), expected['text'])
                        if 'marker' in expected:
                            self.assertIn(expected['marker'], str(result))
                        if expected.get('stdout_round_trip'):
                            self.assertEqual(hashlib.sha256(str(result).encode('utf-8')).hexdigest(),
                                             hashlib.sha256(stdout.decode('utf-8').strip().encode('utf-8')).hexdigest())
                        if live and case['id'] == 'split-valid-utf8':
                            self.assertNotIn('\ufffd', terminal.getvalue())
                            self.assertIn('\u20ac', terminal.getvalue())
                        if live and expected.get('render_lines'):
                            self.assertIn('  [SCAN] 80/tcp open http', terminal.getvalue())
                            self.assertIn('  [SCAN] 443/tcp open https', terminal.getvalue())
                            self.assertNotIn('\\x0a', terminal.getvalue())
                        captured_limit = sum(min(len(data), process_runner.MAX_CAPTURE_BYTES)
                                             for data in (stdout, stderr))
                        self.assertLessEqual(len(result), captured_limit + 512)
                        typed = run_selected_structured(
                            ScanRequest('example.test', ('1',)),
                            menu={'1': ('nmap', lambda _target, captured=result: captured)})
                        plan = build_custom_plan('example.test', ('1',), active_consent=False)
                        report = scan_report(plan, typed)
                        run = sarif_from_report(report)['runs'][0]
                        self.assertEqual(report['coverage']['status'], expected['coverage'])
                        self.assertEqual([row['rule'] for row in report['findings']], expected['rules'])
                        self.assertEqual(run['properties']['coverage'], report['coverage'])
                        self.assertEqual(run['invocations'][0]['executionSuccessful'],
                                         expected['status'] == 'COMPLETE')
                        self.assertEqual([row['ruleId'] for row in run['results']], expected['rules'])
                        for record in typed.results[0].evidence_records:
                            self.assertTrue(record.matches(typed.results[0]))
                        projections.append((result.status, result.evidence, result.exit_code,
                                            report['coverage'], expected['rules']))
            if len(projections) == 2:
                self.assertEqual(projections[0], projections[1])

    def test_missing_binary_and_denied_start_are_never_evidence(self):
        with tempfile.TemporaryDirectory() as folder:
            missing = str(Path(folder) / 'missing-scanner.exe')
            for live in (False, True):
                with self.subTest(live=live), \
                     patch.dict(os.environ, {'PENX_LIVE_OUTPUT': str(int(live))}), \
                     redirect_stdout(StringIO()):
                    result = process_runner.run_tool([missing], timeout=5)
                    self.assertEqual(result.status, 'FAILED')
                    self.assertFalse(result.evidence)
                    self.assertIsNone(result.exit_code)
                    with patch.object(process_runner.subprocess, 'Popen',
                                      side_effect=PermissionError('synthetic permission denial')):
                        denied = process_runner.run_tool([sys.executable], timeout=5)
                    self.assertEqual(denied.status, 'FAILED')
                    self.assertFalse(denied.evidence)
                    self.assertIsNone(denied.exit_code)


if __name__ == '__main__':
    unittest.main()
