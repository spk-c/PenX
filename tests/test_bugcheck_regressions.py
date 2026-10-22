"""Reproductions for audit findings; synthetic adapters and temporary files only."""
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

from penx_app.application.scan_profiles import build_custom_plan
from penx_app.application.scan_planner import run_plan
from penx_app.domain.scan_models import ScanRequest, ScanResult, ScannerResult, ScannerOutput


class SchedulingAuditTests(unittest.TestCase):
    def test_dispatch_interval_does_not_bypass_completed_508_guard(self):
        selected = build_custom_plan('example.test', ('4', '7'), active_consent=True,
                                     max_parallelism=2, dispatch_interval_seconds=0.15)
        sensitive = Mock(return_value=ScannerOutput('Must never run'))
        result = run_plan(selected, menu={
            '4': ('HTTP headers', lambda target: ScannerOutput('HTTP 508 Resource Limit Is Reached')),
            '7': ('Nuclei', sensitive)})
        sensitive.assert_not_called()
        self.assertEqual(result.results[1].status, 'PARTIAL')

    def test_dispatch_wait_keeps_node_deadlines_responsive(self):
        observed = []
        def adapter(target, *, cancel_event=None):
            started = time.monotonic()
            cancel_event.wait(1)
            observed.append(time.monotonic() - started)
            return ScannerOutput('Stopped', status='PARTIAL', evidence=False)
        selected = build_custom_plan('example.test', ('1', '2'), active_consent=False,
                                     max_parallelism=2, dispatch_interval_seconds=0.4)
        with patch('penx_app.application.scan_planner.resolve_node_timeout', return_value=0.03):
            run_plan(selected, menu={'1': ('Nmap', adapter),
                                     '2': ('Whois', lambda target: ScannerOutput('Registry response'))})
        self.assertLess(observed[0], 0.25, 'dispatch wait prevented deadline signaling')

    def test_interrupt_signals_inflight_workers_before_pool_shutdown(self):
        started = threading.Event()
        saw_cancel = []
        def waiting(target, *, cancel_event=None):
            started.set()
            saw_cancel.append(cancel_event.wait(0.8))
            return ScannerOutput('Stopped', status='PARTIAL', evidence=False)
        def interrupted(target):
            self.assertTrue(started.wait(1))
            raise KeyboardInterrupt()
        selected = build_custom_plan('example.test', ('1', '2'), active_consent=False, max_parallelism=2)
        with self.assertRaises(KeyboardInterrupt):
            run_plan(selected, menu={'1': ('Nmap', waiting), '2': ('Whois', interrupted)})
        self.assertEqual(saw_cancel, [True])

    def test_legacy_request_does_not_accept_truthy_text_as_consent(self):
        from penx_app.application.scanner_execution import run_selected
        scanner = Mock(return_value=ScannerOutput('Must never run'))
        for value in ('false', 1, None):
            with self.subTest(value=value), self.assertRaises(ValueError):
                run_selected(ScanRequest('example.test', ('7',), active_consent=value), menu={'7': ('Nuclei', scanner)})
        scanner.assert_not_called()


class ScannerAndReportAuditTests(unittest.TestCase):
    def test_capped_native_summary_cannot_pass_coverage_policy(self):
        from penx_app.scanners.tools import _summarize_native_run
        from penx_app.application.headless_scan import scan_report, policy_exit
        rows = [json.dumps({'template-id': f'rule-{i}', 'info': {'severity': 'low', 'name': 'Sample'},
                            'matched-at': 'https://example.test/'}) for i in range(60)]
        rows.append(json.dumps({'template-id': 'hidden-critical', 'info': {'severity': 'critical', 'name': 'Sample'},
                                'matched-at': 'https://example.test/'}))
        output = _summarize_native_run('nuclei', ScannerOutput('\n'.join(rows)))
        self.assertEqual(output.status, 'PARTIAL')
        result = ScanResult((ScannerResult('nuclei', str(output), output.status, output.evidence),))
        selected = build_custom_plan('example.test', ('7',), active_consent=True)
        self.assertEqual(policy_exit(result, scan_report(selected, result)['findings'], 'high'), 5)

    def test_headless_finding_cap_is_explicit_and_cannot_pass_policy(self):
        from penx_app.application.headless_scan import main
        lines = '\n'.join(f'TEMPLATE rule-{i} | low | Sample observation | https://example.test/{i}' for i in range(1001))
        result = ScanResult((ScannerResult('nuclei', lines, 'COMPLETE', True),))
        with tempfile.TemporaryDirectory() as folder, patch('penx_app.application.headless_scan.run_plan', return_value=result):
            code = main(['--target', 'example.test', '--scanners', '7', '--consent', '--authorized',
                         '--output', folder, '--fail-on', 'high'])
            saved = json.loads((Path(folder) / 'penx_scan.json').read_text())
        self.assertEqual(code, 5)
        self.assertTrue(saved['findings_truncated'])
        self.assertEqual(len(saved['findings']), 1000)

    def test_conflicting_duplicate_nuclei_severities_do_not_hide_highest(self):
        from penx_app.application.headless_scan import scan_report
        selected = build_custom_plan('example.test', ('7',), active_consent=True)
        text = ('TEMPLATE same | low | Sample observation | https://example.test/\n'
                'TEMPLATE same | critical | Sample observation | https://example.test/')
        report = scan_report(selected, ScanResult((ScannerResult('nuclei', text, 'COMPLETE', True),)))
        self.assertEqual(len(report['findings']), 1)
        self.assertEqual(report['findings'][0]['severity'], 'critical')

    def test_headless_sarif_retains_failed_execution_and_coverage(self):
        from penx_app.application.headless_scan import scan_report
        from penx_app.reporting.machine_reports import sarif_from_report
        selected = build_custom_plan('example.test', ('1',), active_consent=False)
        result = ScanResult((ScannerResult('nmap', '', 'FAILED', False, diagnostics='Executable missing'),))
        report = scan_report(selected, result)
        report.update(exit_code=4, policy={'fail_on': 'high'})
        run = sarif_from_report(report)['runs'][0]
        self.assertFalse(run['invocations'][0]['executionSuccessful'])
        self.assertEqual(run['properties']['coverage']['status'], 'PARTIAL')
        self.assertEqual(run['properties']['exitCode'], 4)


class PublicationAuditTests(unittest.TestCase):
    def test_report_publication_survives_more_than_101_collisions(self):
        from penx_app.file_output import publish_unique
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for index in range(101):
                (root / f'report{("_" + str(index)) if index else ""}.json').write_text('preserve')
            path = publish_unique(root, 'report', '.json', 'new complete report')
            self.assertEqual(path.read_text(), 'new complete report')
            self.assertEqual((root / 'report_100.json').read_text(), 'preserve')

    def test_publication_rejects_filename_traversal(self):
        from penx_app.file_output import publish_unique
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(ValueError):
                publish_unique(Path(folder) / 'exports', '../escaped', '.json', 'outside')
            self.assertFalse((Path(folder) / 'escaped.json').exists())

    def test_identical_retained_artifact_is_reused_and_integrity_checked(self):
        from penx_app.storage.raw_artifacts import retain_artifacts, validate_artifact
        result = ScanResult((ScannerResult('nmap', 'Exact trusted capture', 'COMPLETE', True),))
        with tempfile.TemporaryDirectory() as folder:
            first = retain_artifacts(result, folder)
            second = retain_artifacts(result, folder)
            self.assertEqual(first.results[0].raw_artifact, second.results[0].raw_artifact)
            self.assertEqual(len(list(Path(folder).iterdir())), 1)
            ref = first.results[0].raw_artifact
            (Path(folder) / ref.filename).write_text('Corrupted original')
            replacement = retain_artifacts(result, folder)
            self.assertNotEqual(replacement.results[0].raw_artifact.filename, ref.filename)
            self.assertEqual(validate_artifact(replacement.results[0], folder).text, result.results[0].text)

    def test_diff_export_preserves_existing_companions(self):
        from penx_app.application.scan_trends import compare_sessions, export_diff_reports
        def session(number):
            return {'history': (number, 'example.test', 'today', 'active'), 'summary': None,
                    'vulns': [], 'corrections': []}
        delta = compare_sessions(session(1), session(2))
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for suffix in ('.html', '.pdf'):
                (root / ('diff_example_test_1_2' + suffix)).write_bytes(b'preserve foreign file')
            files = export_diff_reports(delta, root)
            for suffix in ('.html', '.pdf'):
                self.assertEqual((root / ('diff_example_test_1_2' + suffix)).read_bytes(), b'preserve foreign file')
            self.assertTrue(files['pdf'].read_bytes().startswith(b'%PDF'))


class ReviewBudgetAuditTests(unittest.TestCase):
    def test_minimum_valid_batch_budget_admits_one_review(self):
        from penx_app.application.local_review import main
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / 'input.json'
            source.write_text('{}')
            with patch('penx_app.application.local_review.time.monotonic', side_effect=[10, 10.001]), \
                    patch('penx_app.application.local_review.create_review', return_value={}) as review:
                code = main([str(source), '--model', 'local', '--batch-budget', '5', '--output', folder])
            self.assertEqual(code, 0)
            review.assert_called_once()


if __name__ == '__main__':
    unittest.main()
