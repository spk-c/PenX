"""Offline regression cases for lossy native scanner parsing."""
import json
import unittest

from penx_app.application.headless_scan import scan_report
from penx_app.application.scan_profiles import build_custom_plan
from penx_app.domain.scan_models import ScanResult, ScannerResult
from penx_app.scanners.tools import _summarize_native_run


class NativeParserAuditTests(unittest.TestCase):
    def match(self, **changes):
        row = {'template-id': 'example-check',
               'info': {'severity': 'critical', 'name': 'Example finding'},
               'matched-at': 'https://example.test/'}
        row.update(changes)
        return json.dumps(row)

    def report(self, output):
        plan = build_custom_plan('example.test', ('7',), active_consent=True)
        return scan_report(plan, ScanResult(results=(
            ScannerResult(display_name='Nuclei', text=str(output), scanner_id='nuclei',
                          status=output.status, evidence=output.evidence),)))

    def test_mixed_malformed_json_is_not_complete(self):
        for scanner, valid in (
                ('nuclei', self.match()),
                ('httpx', json.dumps({'url': 'https://example.test/', 'status_code': 200})),
                ('ffuf', json.dumps({'url': 'https://example.test/', 'status': 200}))):
            for invalid in ('broken secret-token', '[]', '{}', 'x' * 1_000_001):
                with self.subTest(scanner=scanner, invalid=invalid[:20]):
                    output = _summarize_native_run(scanner, valid + '\n' + invalid)
                    self.assertEqual(output.status, 'PARTIAL')
                    self.assertTrue(output.evidence)
                    self.assertNotIn('secret-token', str(output) + output.diagnostics)

    def test_pipes_in_template_or_name_do_not_hide_critical_findings(self):
        for changes in ({'template-id': 'check|suffix'},
                        {'info': {'severity': 'critical', 'name': 'Name | detail'}}):
            with self.subTest(changes=changes):
                report = self.report(_summarize_native_run('nuclei', self.match(**changes)))
                self.assertEqual(len(report['findings']), 1)
                self.assertEqual(report['findings'][0]['severity'], 'critical')

    def test_uppercase_severity_and_missing_name_keep_finding(self):
        output = _summarize_native_run('nuclei', self.match(info={'severity': 'CRITICAL'}))
        report = self.report(output)
        self.assertEqual(len(report['findings']), 1)
        self.assertEqual(report['findings'][0]['severity'], 'critical')

    def test_escaped_template_identities_remain_distinct(self):
        raw = '\n'.join(self.match(**{'template-id': identity})
                        for identity in ('check|suffix', 'check/suffix', 'check%7Csuffix', '|' * 120))
        report = self.report(_summarize_native_run('nuclei', raw))
        self.assertEqual(len(report['findings']), 4)

    def test_unknown_severity_cannot_be_complete_coverage(self):
        output = _summarize_native_run('nuclei', self.match(info={'severity': 'unexpected'}))
        self.assertEqual(output.status, 'PARTIAL')

    def test_nmap_observations_do_not_silently_stop_at_100(self):
        plan = build_custom_plan('example.test', ('1',), active_consent=False)
        text = '\n'.join(f'{port}/tcp open test-service' for port in range(1, 102))
        report = scan_report(plan, ScanResult((ScannerResult('nmap', text, 'COMPLETE', True),)))
        self.assertEqual(len(report['findings']), 101)

    def test_non_nuclei_input_truncation_is_explicit(self):
        plan = build_custom_plan('example.test', ('1',), active_consent=False)
        text = 'x' * 1_048_577
        report = scan_report(plan, ScanResult((ScannerResult('nmap', text, 'COMPLETE', True),)))
        self.assertTrue(report['findings_truncated'])


if __name__ == '__main__':
    unittest.main()
