"""Synthetic stored-data and comparison regressions; no external I/O."""
import json
import unittest

from penx_app.application.scan_trends import _ports, canonical_target, compare_sessions
from penx_app.domain.scan_models import ScannerOutput, ScannerResult, ScanResult
from penx_app.reporting.scan_coverage import coverage


def session(number, raw):
    return {'history': (number, 'example.test', '2026-10-22', 'active'),
            'summary': (number, number, raw, 'fixture', 'LOW'),
            'vulns': [], 'corrections': []}


class MetadataAndDiffAuditTests(unittest.TestCase):
    def test_evidence_flags_must_be_boolean(self):
        for flag in ('false', 'true', 0, 1, None, [], {}):
            for constructor in (
                    lambda _f=flag: ScannerResult('nmap', '80/tcp open http', 'COMPLETE', _f),
                    lambda _f=flag: ScannerOutput('80/tcp open http', evidence=_f)):
                with self.subTest(flag=flag, constructor=constructor):
                    with self.assertRaises(ValueError):
                        constructor()

    def test_duplicate_json_fields_cannot_override_failed_metadata(self):
        for text in (
                '{"version":999,"version":1,"adapters":[]}',
                '{"version":1,"adapters":[{"id":"nmap","name":"Nmap",'
                '"status":"FAILED","status":"COMPLETE","evidence":false}]}'):
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    ScanResult.from_metadata(text)

    def test_nmap_failures_override_success_footer_in_diffs(self):
        base = '[ NMAP OUTPUT ]\n80/tcp open http\nNmap done: 1 IP address scanned\n'
        for error in ('[EXIT CODE -9]', '[!] OUTPUT TRUNCATED: incomplete capture',
                      '[!] Scanner cancelled.', '[PARTIAL OUTPUT]',
                      '[PENX ADAPTER STATUS: PARTIAL; EVIDENCE: NO]'):
            with self.subTest(error=error):
                newer = session(2, '[ NMAP OUTPUT ]\n' + error + '\nNmap done: 1 IP address scanned\n')
                diff = compare_sessions(session(1, base), newer)
                self.assertFalse(diff['port_comparison_reliable'])
                self.assertEqual(diff['missing_ports'], {})

    def test_legacy_coverage_rejects_negative_exit_code(self):
        result = coverage('[ NMAP OUTPUT ]\n[EXIT CODE -9]\n80/tcp open http\n')
        self.assertEqual(result['status'], 'PARTIAL')

    def test_duplicate_nmap_sections_cannot_establish_complete_ports(self):
        raw = ('[ NMAP OUTPUT ]\n80/tcp open http\nNmap done: 1 IP address scanned\n'
               '[ NMAP OUTPUT ]\n[!] Timed out\n')
        _, reliable = _ports(session(1, raw))
        self.assertFalse(reliable)

    def test_broken_structured_xml_does_not_fall_back_to_success_footer(self):
        raw = ('[ NMAP OUTPUT ]\n80/tcp open http\nNmap done: 1 IP address scanned\n'
               '[NMAP STRUCTURED XML]\n<nmaprun><broken></nmaprun>')
        _, reliable = _ports(session(1, raw))
        self.assertFalse(reliable)

    def test_valid_metadata_stays_round_trip_compatible(self):
        original = ScanResult((ScannerResult('nmap', 'sample', 'COMPLETE', True, 'Nmap'),))
        saved = original.metadata()
        self.assertEqual(json.loads(ScanResult.from_metadata(saved).metadata()), json.loads(saved))

    def test_case_sensitive_url_scopes_cannot_be_compared_as_same_target(self):
        for previous, latest in (
                ('https://example.test/Admin', 'https://example.test/admin'),
                ('https://example.test/?key=A', 'https://example.test/?key=a'),
                ('https://example.test/admin/', 'https://example.test/admin')):
            with self.subTest(previous=previous, latest=latest):
                older, newer = session(1, ''), session(2, '')
                older['history'] = (1, previous, '2026-10-22', 'active')
                newer['history'] = (2, latest, '2026-10-22', 'active')
                with self.assertRaises(ValueError):
                    compare_sessions(older, newer)

    def test_host_case_and_root_slash_still_compare_equally(self):
        self.assertEqual(canonical_target(' HTTPS://EXAMPLE.TEST/ '),
                         canonical_target('https://example.test'))
        self.assertEqual(canonical_target('EXAMPLE.TEST'), canonical_target('example.test/'))
        self.assertEqual(canonical_target('https://EXAMPLE.TEST/Admin?key=A'),
                         canonical_target('https://example.test/Admin?key=A'))


if __name__ == '__main__':
    unittest.main()
