"""Offline acceptance tests for stable identity and retained raw evidence."""
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from penx_app.application.assessment_service import AssessmentPorts, run_assessment
from penx_app.application.scan_trends import compare_sessions, report_text
from penx_app.domain.evidence import capture_evidence
from penx_app.domain.finding_identity import finding_fingerprint
from penx_app.domain.raw_artifact import MAX_ARTIFACT_BYTES, RawArtifact
from penx_app.domain.scan_diagnostics import PlanSummary
from penx_app.domain.scan_models import ReconText, ScanResult, ScannerResult
from penx_app.reporting.machine_reports import report_payload, sarif_payload
from penx_app.storage.raw_artifacts import retain_artifacts, validate_artifact


def session(number=1, *, profile='standard', scanner='nmap', severity='low'):
    quote = '80/tcp open http Example server'
    adapter = ScannerResult(scanner, quote, 'COMPLETE', True, scanner.upper())
    adapter = replace(adapter, evidence_records=(capture_evidence(
        adapter, 0, len(quote), kind='adapter_output', parser_version=1),))
    return {
        'history': (number, 'example.test', '2026-10-22', 'active'),
        'summary': (number, number, '[ NMAP OUTPUT ]\n' + quote + '\nNmap done:', 'Analysis', 'LOW'),
        'vulns': [(number, number, 'Open HTTP service', severity, 'possible',
                   '80', 'http', 'Evidence: ' + quote)],
        'corrections': [], 'fixes': [],
        'scan_result': ScanResult((adapter,), PlanSummary(profile, 1, 1, None)),
    }


class Phase2TraceabilityTests(unittest.TestCase):
    def test_identity_ignores_storage_ids_dates_and_severity(self):
        old, new = session(1), session(999, severity='high')
        new['history'] = (999, 'example.test', '2027-01-01', 'active')
        diff = compare_sessions(old, new)
        self.assertEqual(len(diff['severity_changes']), 1)
        fingerprint = diff['severity_changes'][0]['finding']['fingerprint']
        self.assertEqual(fingerprint, report_payload(old)['findings'][0]['fingerprint'])
        self.assertEqual(fingerprint, report_payload(new)['findings'][0]['fingerprint'])
        self.assertEqual(sarif_payload(new)['runs'][0]['results'][0]['properties']['findingFingerprint'], fingerprint)

    def test_identity_normalizes_case_whitespace_unicode_only(self):
        def fp(name, target='example.test', port='80', service='http'):
            return finding_fingerprint(name, port, service, target=target)
        self.assertEqual(fp('Caf\u00e9  Issue'), fp(' CAFE\u0301 issue '))
        for other in (fp('Other issue'), fp('Caf\u00e9 Issue', target='other.test'),
                      fp('Caf\u00e9 Issue', port='443'), fp('Caf\u00e9 Issue', service='https')):
            self.assertNotEqual(fp('Caf\u00e9 Issue'), other)

    def test_selection_and_profile_changes_are_explicit(self):
        diff = compare_sessions(session(), session(2, profile='web_audit', scanner='httpx'))
        self.assertTrue(any('selections differ' in note for note in diff['comparability_notes']))
        self.assertTrue(any('configuration differ' in note for note in diff['comparability_notes']))
        text = report_text(diff)
        self.assertIn('web_audit', text)
        self.assertIn('HTTPX', text)
        self.assertEqual(diff['scan_context']['previous']['plan']['profile_id'], 'standard')

    def test_legacy_context_does_not_invent_a_profile(self):
        old = session()
        old.pop('scan_result')
        diff = compare_sessions(old, session(2))
        self.assertIsNone(diff['scan_context']['previous']['plan'])
        self.assertIsNone(diff['scan_context']['previous']['scanner_ids'])
        self.assertTrue(any('unknown' in note for note in diff['comparability_notes']))

    def test_artifact_preserves_utf8_and_mixed_line_endings(self):
        for text in ('first\nsecond\r\nlast', 'Pr\u00fcfung\n\u2603'):
            with self.subTest(text=text), tempfile.TemporaryDirectory() as root:
                adapter = replace(session()['scan_result'].results[0], text=text, evidence_records=())
                stored = retain_artifacts(ScanResult((adapter,)), root)
                ref = stored.results[0].raw_artifact
                self.assertEqual(ref.sha256, hashlib.sha256(text.encode('utf-8')).hexdigest())
                self.assertEqual((Path(root) / ref.filename).read_bytes(), text.encode('utf-8'))
                restored = ScanResult.from_metadata(stored.metadata())
                self.assertEqual(restored.results[0].text, '')
                self.assertEqual(validate_artifact(restored.results[0], root).text, text)

    def test_artifact_metadata_and_anchor_revalidation(self):
        with tempfile.TemporaryDirectory() as root:
            data = session()
            stored = retain_artifacts(data['scan_result'], root)
            data['scan_result'] = ScanResult.from_metadata(stored.metadata())
            adapter = data['scan_result'].results[0]
            validate_artifact(adapter, root)
            finding = report_payload(data)['findings'][0]
            self.assertEqual(finding['raw_artifact']['sha256'], adapter.raw_artifact.sha256)
            self.assertEqual(finding['artifact_status'], 'stored-reference-not-revalidated')
            bad = replace(adapter.evidence_records[0], quote='X' * len(adapter.text or adapter.evidence_records[0].quote))
            with self.assertRaisesRegex(ValueError, 'anchors'):
                validate_artifact(replace(adapter, evidence_records=(bad,)), root)

    def test_tampered_missing_and_oversized_files_fail_closed(self):
        with tempfile.TemporaryDirectory() as root:
            stored = retain_artifacts(session()['scan_result'], root).results[0]
            path = Path(root) / stored.raw_artifact.filename
            with patch('os.open', side_effect=FileNotFoundError):
                with self.assertRaises(FileNotFoundError):
                    validate_artifact(stored, root)
            for content in (b'changed', b'x' * (MAX_ARTIFACT_BYTES + 1)):
                # Test fixture mutation through a temporary file handle.
                with path.open('wb') as handle:
                    handle.write(content)
                with self.assertRaisesRegex(ValueError, 'integrity'):
                    validate_artifact(stored, root)

    def test_invalid_refs_and_legacy_versions_reject_artifacts(self):
        for changes in ({'filename': '../capture.txt'}, {'sha256': 'x' * 64},
                        {'size_bytes': True}, {'size_bytes': MAX_ARTIFACT_BYTES + 1},
                        {'validator': 'unknown'}):
            values = dict(sha256='a' * 64, size_bytes=1, filename='a' * 64 + '.txt')
            values.update(changes)
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                RawArtifact(**values)
        with tempfile.TemporaryDirectory() as root:
            payload = json.loads(retain_artifacts(session()['scan_result'], root).metadata())
            for version in (1, 2):
                payload['version'] = version
                with self.assertRaises(ValueError):
                    ScanResult.from_metadata(json.dumps(payload))

    def test_bounds_and_unavailable_adapters_are_not_retained(self):
        with tempfile.TemporaryDirectory() as root:
            for adapter in (
                ScannerResult('nmap', 'error', 'FAILED', False),
                ScannerResult('nmap', 'x' * (MAX_ARTIFACT_BYTES + 1), 'COMPLETE', True),
                ScannerResult('nmap', '\u2603' * MAX_ARTIFACT_BYTES, 'COMPLETE', True),
            ):
                self.assertIsNone(retain_artifacts(ScanResult((adapter,)), root).results[0].raw_artifact)
            self.assertEqual(list(Path(root).iterdir()), [])

    def test_assessment_retention_is_opt_in(self):
        data = session()
        raw = ReconText(data['summary'][2], data['scan_result'])
        saved = []
        ports = AssessmentPorts(lambda *a, **k: 1, lambda *a: {},
                                lambda i, result, **k: saved.append(result) or {},
                                lambda *a: None, lambda *a: None, lambda *a: {})
        with tempfile.TemporaryDirectory() as root:
            for enabled in (False, True):
                with patch.dict('os.environ', {'PENX_RAW_ARTIFACT_DIR': root if enabled else ''}):
                    outcome = run_assessment('example.test', raw, raw.result.coverage(),
                                             passive_only=False, model_name='fixture', ports=ports)
                self.assertTrue(outcome.completed)
                restored = ScanResult.from_metadata(saved[-1]['scan_metadata'])
                self.assertEqual(restored.results[0].raw_artifact is not None, enabled)


if __name__ == '__main__':
    unittest.main()
