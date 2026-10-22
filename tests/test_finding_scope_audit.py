"""Endpoint-sensitive finding identity without external scans."""
import hashlib
import json
import unittest

from penx_app.application.headless_scan import scan_report
from penx_app.application.scan_profiles import build_custom_plan
from penx_app.application.scan_trends import compare_sessions
from penx_app.domain.finding_identity import finding_fingerprint
from penx_app.domain.scan_models import ScanResult, ScannerResult
from penx_app.reporting.machine_reports import report_payload


class FindingScopeAuditTests(unittest.TestCase):
    def test_label_only_legacy_identities_are_unchanged(self):
        content = ['example.test', 'example finding', '80', 'http']
        expected = 'penx-finding-v1:' + hashlib.sha256(
            json.dumps(content, ensure_ascii=True, separators=(',', ':')).encode()).hexdigest()
        self.assertEqual(finding_fingerprint(' Example  Finding ', '80', 'HTTP',
                                            target='EXAMPLE.TEST'), expected)

    def test_url_host_case_is_normalized_but_target_path_case_is_not(self):
        def fp(target, location):
            return finding_fingerprint('Example finding', location, 'http', target=target)
        self.assertEqual(fp('https://EXAMPLE.TEST/Admin', 'https://EXAMPLE.TEST/Path'),
                         fp('https://example.test/Admin', 'https://example.test/Path'))
        self.assertNotEqual(fp('https://example.test/Admin', '80'),
                            fp('https://example.test/admin', '80'))

    def test_nuclei_distinct_paths_and_template_ids_are_not_merged(self):
        plan = build_custom_plan('example.test', ('7',), active_consent=True)
        identities = [('check', 'https://example.test/Admin'),
                      ('check', 'https://example.test/admin'),
                      ('Check', 'https://example.test/admin'),
                      ('check', 'https://example.test/?key=A'),
                      ('check', 'https://example.test/?key=a')]
        raw = '\n'.join(f'TEMPLATE {rule} | high | Example finding | {url}' for rule, url in identities)
        report = scan_report(plan, ScanResult((ScannerResult('nuclei', raw, 'COMPLETE', True),)))
        self.assertEqual(len(report['findings']), len(identities))
        self.assertEqual(len({row['fingerprint'] for row in report['findings']}), len(identities))

    def test_nikto_paths_preserve_case_in_identity(self):
        plan = build_custom_plan('example.test', ('6',), active_consent=True)
        raw = '+ /Admin: Example observation requires review\n+ /admin: Example observation requires review'
        report = scan_report(plan, ScanResult((ScannerResult('nikto', raw, 'COMPLETE', True),)))
        self.assertEqual(len(report['findings']), 2)

    def test_url_scopes_do_not_casefold_path_query_or_trailing_slash(self):
        def fp(location):
            return finding_fingerprint('Example finding', location, 'http', target='example.test')
        for a, b in (('https://example.test/Admin', 'https://example.test/admin'),
                     ('https://example.test/?id=A', 'https://example.test/?id=a'),
                     ('https://example.test/admin/', 'https://example.test/admin')):
            with self.subTest(a=a, b=b):
                self.assertNotEqual(fp(a), fp(b))

    def test_export_and_comparison_use_same_root_target_identity(self):
        def session(number, target):
            return {'history': (number, target, '2026-10-22', 'active'),
                    'summary': (number, number, '', 'Synthetic', 'LOW'),
                    'vulns': [(number, number, 'Example finding', 'low', 'possible', '80', 'http', '')],
                    'corrections': [], 'fixes': []}
        previous = session(1, 'https://example.test/?')
        latest = session(2, 'https://example.test')
        diff = compare_sessions(previous, latest)
        identity = diff['persistent_findings'][0]['fingerprint']
        self.assertEqual(report_payload(previous)['findings'][0]['fingerprint'], identity)
        self.assertEqual(report_payload(latest)['findings'][0]['fingerprint'], identity)


if __name__ == '__main__':
    unittest.main()
