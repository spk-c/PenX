"""Native field-loss and diagnostic attribution regressions (offline only)."""
import json
import unittest

from penx_app.domain.scan_models import ScannerOutput
from penx_app.scanners.tools import _summarize_native_run


class NativeLossAuditTests(unittest.TestCase):
    def test_clipped_template_identity_is_partial(self):
        raw = json.dumps({'template-id': 'a' * 121,
                          'info': {'severity': 'high', 'name': 'Example'},
                          'matched-at': 'https://example.test/'})
        self.assertEqual(_summarize_native_run('nuclei', raw).status, 'PARTIAL')

    def test_clipped_endpoint_identity_is_partial_for_all_native_scanners(self):
        url = 'https://example.test/' + 'a' * 230
        for scanner, row in (
                ('nuclei', {'template-id': 'example', 'info': {'severity': 'high', 'name': 'Example'}, 'matched-at': url}),
                ('httpx', {'url': url, 'status_code': 200}),
                ('ffuf', {'url': url, 'status': 200})):
            with self.subTest(scanner=scanner):
                self.assertEqual(_summarize_native_run(scanner, json.dumps(row)).status, 'PARTIAL')

    def test_invalid_endpoints_never_establish_completed_evidence(self):
        for url in ('ftp://example.test/a', 'https://example.test:bad/a',
                    'https://example.test:0/a', 'https://[::invalid',
                    'https://user:SECRET@example.test/a'):
            with self.subTest(url=url):
                output = _summarize_native_run('httpx', json.dumps({'url': url, 'status_code': 200}))
                self.assertEqual(output.status, 'FAILED')
                self.assertFalse(output.evidence)
                self.assertNotIn('SECRET', str(output) + output.diagnostics)

    def test_ffuf_json_field_cannot_impersonate_timeout_diagnostic(self):
        raw = json.dumps({'url': 'https://example.test/a', 'status': 200,
                          'input': {'FUZZ': 'Maximum running time for entire process reached'}})
        output = _summarize_native_run('ffuf', raw)
        self.assertEqual(output.status, 'COMPLETE')

    def test_ffuf_crash_is_not_reclassified_as_time_limit(self):
        for code in (-9, 2):
            text = f'[EXIT CODE {code}]\nMaximum running time for entire process reached'
            for raw in (text, ScannerOutput(text, status='FAILED', evidence=False, exit_code=code)):
                with self.subTest(code=code, typed=isinstance(raw, ScannerOutput)):
                    self.assertEqual(_summarize_native_run('ffuf', raw).status, 'FAILED')

    def test_long_query_redaction_does_not_count_as_identity_clipping(self):
        raw = json.dumps({'url': 'https://example.test/a?token=' + 'SECRET' * 100,
                          'status_code': 200})
        output = _summarize_native_run('httpx', raw)
        self.assertEqual(output.status, 'COMPLETE')
        self.assertNotIn('SECRET', output)

    def test_at_sign_outside_url_authority_is_not_mistaken_for_credentials(self):
        for url in ('https://example.test/a?user=SECRET@example.test',
                    'example.test/a?user=SECRET@example.test',
                    'https://example.test/public/@route'):
            with self.subTest(url=url):
                output = _summarize_native_run('httpx', json.dumps({'url': url, 'status_code': 200}))
                self.assertEqual(output.status, 'COMPLETE')
                self.assertNotIn('SECRET', output)

    def test_whitespace_only_template_is_not_evidence(self):
        row = {'template-id': '   ', 'info': {'severity': 'high', 'name': 'Example'},
               'matched-at': 'https://example.test/'}
        output = _summarize_native_run('nuclei', json.dumps(row))
        self.assertEqual(output.status, 'FAILED')
        self.assertFalse(output.evidence)


if __name__ == '__main__':
    unittest.main()
