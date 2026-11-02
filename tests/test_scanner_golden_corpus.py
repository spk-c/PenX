"""PX-003: immutable synthetic JSONL inputs through real parsers and exports."""
from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from penx_app.application.headless_scan import scan_report
from penx_app.application.scan_profiles import build_custom_plan
from penx_app.application.scanner_execution import run_selected_structured
from penx_app.domain.scan_models import ScanRequest, ScannerOutput
from penx_app.reporting.machine_reports import sarif_from_report
from penx_app.scanners.registry import SCANNERS
from penx_app.scanners.tools import _summarize_native_run

PACK = ROOT / 'tests/fixtures/scanner_corpus/native_jsonl_v1.json'


class ScannerGoldenCorpusTests(unittest.TestCase):
    def setUp(self):
        self.pack = json.loads(PACK.read_text(encoding='utf-8'))
        # Unexpected I/O is a failure, even when an adapter catches the exception.
        self.guards = []
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        for name in ('socket.socket.connect', 'socket.socket.connect_ex',
                     'socket.socket.sendto', 'socket.getaddrinfo',
                     'subprocess.Popen', 'requests.Session.request'):
            guard = self.stack.enter_context(patch(name, side_effect=AssertionError('Offline corpus I/O')))
            self.guards.append(guard)

    def tearDown(self):
        for guard in self.guards:
            guard.assert_not_called()

    def test_fixture_provenance_and_unique_ids(self):
        self.assertEqual(self.pack['schema'], 'penx-scanner-corpus-v1')
        self.assertEqual(self.pack['provenance']['kind'], 'hand-authored-synthetic')
        cases = self.pack['cases']
        self.assertEqual(len({case['id'] for case in cases}), len(cases))
        self.assertEqual({case['scanner'] for case in cases}, {'nuclei', 'httpx', 'ffuf'})
        for case in cases:
            with self.subTest(case=case['id']):
                raw = '\n'.join(case['stdout'])
                self.assertEqual(hashlib.sha256(raw.encode('utf-8')).hexdigest(), case['sha256'])

    def test_parser_outcome_and_json_sarif_parity(self):
        keys = {spec.id: key for key, spec in SCANNERS.items()}
        for case in self.pack['cases']:
            with self.subTest(case=case['id']):
                scanner, expected = case['scanner'], case['expected']
                raw = '\n'.join(case['stdout'])
                # The process boundary is supplied; actual parsing, dispatch,
                # evidence capture and report builders remain in use.
                process = ScannerOutput(raw, status=case.get('process_status', 'COMPLETE'),
                                        evidence=False)
                output = _summarize_native_run(scanner, process)
                self.assertEqual(output.status, expected['status'])
                self.assertEqual(output.evidence, expected['evidence'])
                self.assertEqual(str(output), expected['summary'])
                self.assertEqual(output.diagnostics, expected.get('diagnostics', ''))
                for secret in case.get('must_not_publish', []):
                    self.assertNotIn(secret, str(output) + output.diagnostics)
                key = keys[scanner]
                result = run_selected_structured(
                    ScanRequest('example.test', (key,), active_consent=True),
                    menu={key: (scanner, lambda _target, captured=output: captured)})
                plan = build_custom_plan('example.test', (key,), active_consent=True)
                report = scan_report(plan, result)
                # Snapshot only stable public fields, excluding timestamps.
                self.assertEqual(report['schema'], 'penx-scan-v1')
                self.assertEqual(report['adapters'][0]['status'], expected['status'])
                self.assertEqual(report['adapters'][0]['evidence'], expected['evidence'])
                self.assertEqual(report['coverage']['status'], expected['coverage'])
                self.assertEqual([row['rule'] for row in report['findings']], expected['rules'])
                run = sarif_from_report(report)['runs'][0]
                self.assertEqual(run['properties']['coverage'], report['coverage'])
                self.assertEqual(run['invocations'][0]['executionSuccessful'],
                                 expected['coverage'] == 'COMPLETE')
                self.assertEqual([row['ruleId'] for row in run['results']], expected['rules'])
                adapter = result.results[0]
                self.assertEqual(bool(adapter.evidence_records), expected['evidence'])
                for record in adapter.evidence_records:
                    self.assertTrue(record.matches(adapter))
                    self.assertEqual(adapter.text[record.raw_start:record.raw_end], record.quote)
                for finding, sarif in zip(report['findings'], run['results'], strict=True):
                    self.assertIn(finding['raw_evidence'], adapter.text)
                    self.assertEqual(sarif['properties']['evidenceRef'], finding['evidence_ref'])
                    self.assertEqual(sarif['properties']['scannerStatus'], expected['status'])

    def test_http_status_type_and_bounds_mutations(self):
        for scanner, field in (('httpx', 'status_code'), ('ffuf', 'status')):
            seed = next(case for case in self.pack['cases'] if case['id'] == scanner + '-response')
            row = json.loads(seed['stdout'][0])
            for invalid in (None, True, False, 0, 99, 600, 200.0, '200', [], {}):
                with self.subTest(scanner=scanner, invalid=invalid):
                    raw = json.dumps({**row, field: invalid})
                    output = _summarize_native_run(scanner, raw)
                    self.assertEqual(output.status, 'FAILED')
                    self.assertFalse(output.evidence)
            for valid in (100, 200, 403, 429, 500, 599):
                with self.subTest(scanner=scanner, valid=valid):
                    output = _summarize_native_run(scanner, json.dumps({**row, field: valid}))
                    self.assertEqual(output.status, 'COMPLETE')
                    self.assertTrue(output.evidence)

    def test_httpx_error_fields_override_response_claim(self):
        seed = next(case for case in self.pack['cases'] if case['id'] == 'httpx-response')
        row = json.loads(seed['stdout'][0])
        for flags in ({'failed': True}, {'error': 'CORPUS_SECRET'},
                      {'failed': False, 'error': 'CORPUS_SECRET'}):
            with self.subTest(flags=flags):
                output = _summarize_native_run('httpx', json.dumps({**row, **flags}))
                self.assertEqual(output.status, 'FAILED')
                self.assertFalse(output.evidence)
                self.assertNotIn('CORPUS_SECRET', str(output) + output.diagnostics)
        output = _summarize_native_run('httpx', json.dumps({**row, 'failed': False, 'error': ''}))
        self.assertEqual(output.status, 'COMPLETE')
        self.assertTrue(output.evidence)


if __name__ == '__main__':
    unittest.main()
