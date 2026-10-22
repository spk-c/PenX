"""Acceptance regressions for the roadmap gaps, entirely offline."""
from dataclasses import replace
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

from penx_app.application.headless_scan import scan_report, policy_exit
from penx_app.application.passive_execution import run_passive_plan, PassiveStopped
from penx_app.application.profile_documents import ProfileDocument
from penx_app.application.scan_planner import build_schedule, run_plan
from penx_app.application.scan_profiles import build_custom_plan, get_profile, profile_to_plan
from penx_app.domain.scan_models import ScanResult, ScannerResult, ScannerOutput


def plan(keys=('1', '2', '5'), dependencies=()):
    return replace(build_custom_plan('example.test', keys, active_consent=False, max_parallelism=2),
                   dependencies=dependencies)


class DependencyGraphTests(unittest.TestCase):
    def test_stable_topological_schedule_and_no_scope_expansion(self):
        self.assertEqual(build_schedule(plan(dependencies=(('1', '5'),))), ('2', '5', '1'))
        for edges in ((('1', '7'),), (('1', '1'),), (('1', '2'), ('2', '1')), (('1', '2'),) * 2):
            with self.subTest(edges=edges), self.assertRaises(ValueError):
                build_schedule(plan(dependencies=edges))

    def test_dependent_waits_for_actual_parent_completion(self):
        parent_done = threading.Event()
        child_started = threading.Event()
        def parent(target):
            self.assertFalse(child_started.is_set())
            parent_done.set()
            return ScannerOutput('Completed prerequisite')
        def child(target):
            self.assertTrue(parent_done.is_set())
            child_started.set()
            return ScannerOutput('Completed dependent')
        selected = plan(('1', '2'), (('1', '2'),))
        result = run_plan(selected, menu={'1': ('Nmap', child), '2': ('Whois', parent)})
        self.assertTrue(child_started.is_set())
        self.assertEqual([row.scanner_id for row in result.results], ['whois', 'nmap'])
        self.assertEqual(ScanResult.from_metadata(result.metadata()).dependencies, selected.dependencies)

    def test_failed_parent_skips_only_its_descendants(self):
        child = Mock()
        independent = Mock(return_value=ScannerOutput('Independent result'))
        result = run_plan(plan(dependencies=(('1', '2'),)), menu={
            '1': ('Nmap', child), '2': ('Whois', lambda target: ScannerOutput('failure', status='FAILED', evidence=False)),
            '5': ('DNS', independent)})
        child.assert_not_called()
        independent.assert_called_once()
        row = next(row for row in result.results if row.scanner_id == 'nmap')
        self.assertEqual(row.status, 'PARTIAL')
        self.assertIn('prerequisite', row.diagnostics)

    def test_profile_graph_roundtrip_and_cycle_rejection(self):
        document = ProfileDocument('dependent', 1, ('1', '2'), dependencies=(('1', '2'),))
        self.assertEqual(ProfileDocument.from_dict(document.to_dict()), document)
        invalid = document.to_dict()
        invalid['dependencies'] = [['1', '2'], ['2', '1']]
        with self.assertRaises(ValueError):
            ProfileDocument.from_dict(invalid)
        with self.assertRaises(ValueError):
            build_schedule(replace(plan(), active_consent='yes'))

    def test_ready_independent_work_runs_while_prerequisite_is_busy(self):
        release = threading.Event()
        finished = threading.Event()
        def parent(target):
            self.assertTrue(release.wait(1))
            finished.set()
            return ScannerOutput('Prerequisite complete')
        def independent(target):
            release.set()
            return ScannerOutput('Independent complete')
        def child(target):
            self.assertTrue(finished.is_set())
            return ScannerOutput('Dependent complete')
        result = run_plan(plan(dependencies=(('1', '2'),)), menu={
            '1': ('Nmap', child), '2': ('Whois', parent), '5': ('DNS', independent)})
        self.assertTrue(all(row.status == 'COMPLETE' for row in result.results))
        metadata = json.loads(result.metadata())
        metadata['dependencies'] = [['1', '2'], ['2', '1']]
        with self.assertRaises(ValueError):
            ScanResult.from_metadata(json.dumps(metadata))


class PassiveExecutionTests(unittest.TestCase):
    def setUp(self):
        settings = patch.dict('os.environ', {'PENX_SHODAN_INTERNETDB': 'on'})
        settings.start()
        self.addCleanup(settings.stop)

    def passive(self, target='8.8.8.8', budget=30):
        return profile_to_plan(get_profile('passive'), target, active_consent=False, global_budget_seconds=budget)

    def test_precancellation_never_queries_any_provider(self):
        event = threading.Event()
        event.set()
        with patch('penx_app.application.passive_execution._query_json') as query:
            result = run_passive_plan(self.passive(), cancel_event=event)
        query.assert_not_called()
        self.assertTrue(all(row.status == 'PARTIAL' for row in result.results))

    def test_global_budget_stops_current_and_pending_providers(self):
        now = [0]
        def query(*args, **kwargs):
            now[0] = 31
            return {'name': 'Registry response'}
        with patch('penx_app.application.passive_execution._query_json', side_effect=query) as calls:
            result = run_passive_plan(self.passive(), clock=lambda: now[0])
        self.assertEqual(calls.call_count, 1)
        self.assertTrue(all(row.status == 'PARTIAL' for row in result.results))
        self.assertTrue(all(not row.evidence for row in result.results))

    def test_provider_failure_preserves_independent_provider_results(self):
        answer = {'ip': '8.8.8.8', 'ports': [], 'cpes': [], 'tags': [], 'vulns': [], 'hostnames': []}
        with patch('penx_app.application.passive_execution._query_json', side_effect=[ValueError(), answer]):
            result = run_passive_plan(self.passive())
        self.assertEqual([row.status for row in result.results], ['FAILED', 'COMPLETE'])

    def test_dns_and_registry_queries_have_typed_completion(self):
        with patch('dns.resolver.resolve', return_value=[]) as dns, \
                patch('penx_app.application.passive_execution._query_json', side_effect=[[], {'name': 'EXAMPLE'}]):
            result = run_passive_plan(self.passive('example.test'))
        self.assertEqual(dns.call_count, 5)
        self.assertTrue(all(call.kwargs['lifetime'] <= 1 for call in dns.call_args_list))
        self.assertTrue(all(row.status == 'COMPLETE' for row in result.results))

    def test_stream_cancel_closes_http_response(self):
        from penx_app.scanners.passive_recon import _query_json
        stopped = [False]
        def control():
            if stopped[0]:
                raise PassiveStopped('cancelled')
            return 10
        def chunks(**kwargs):
            stopped[0] = True
            yield b'{}'
        response = Mock()
        response.iter_content.side_effect = chunks
        with patch('penx_app.scanners.passive_recon.requests.get', return_value=response) as get, self.assertRaises(PassiveStopped):
            _query_json('https://registry.invalid', control=control)
        response.close.assert_called_once()
        self.assertEqual(get.call_args.kwargs['timeout'], (1, 1))

    def test_cancellation_during_io_exception_remains_partial(self):
        event = threading.Event()
        def query(*args, **kwargs):
            event.set()
            raise TimeoutError()
        with patch('penx_app.application.passive_execution._query_json', side_effect=query):
            result = run_passive_plan(self.passive(), cancel_event=event)
        self.assertTrue(all(row.status == 'PARTIAL' for row in result.results))

    def test_disabled_internetdb_is_never_queried(self):
        with patch.dict('os.environ', {'PENX_SHODAN_INTERNETDB': 'off'}), \
                patch('penx_app.application.passive_execution._query_json', return_value={'name': 'Registry'}) as query:
            result = run_passive_plan(self.passive())
        self.assertEqual(query.call_count, 1)
        self.assertEqual([row.scanner_id for row in result.results], ['passive_rdap'])


class BroaderFindingTests(unittest.TestCase):
    def test_multiple_scanners_produce_scoped_policy_observations(self):
        selected = plan(('1', '4', 'd'))
        rows = (ScannerResult('nmap', '80/tcp open http', 'COMPLETE', True),
                ScannerResult('http_headers', 'Strict-Transport-Security: max-age=0', 'COMPLETE', True),
                ScannerResult('tls', '[VERIFIED TLS HANDSHAKE] example.test:443\nDays remaining: 12', 'COMPLETE', True))
        result = ScanResult(rows)
        report = scan_report(selected, result)
        self.assertEqual({row['scanner'] for row in report['findings']}, {'nmap', 'http_headers', 'tls'})
        self.assertEqual(policy_exit(result, report['findings'], 'low'), 3)
        self.assertEqual(policy_exit(result, report['findings'], 'high'), 0)
        for finding in report['findings']:
            source = next(row for row in rows if row.scanner_id == finding['scanner'])
            self.assertIn(finding['raw_evidence'], source.text)

    def test_missing_headers_failed_tls_and_banner_prose_never_invent_findings(self):
        result = ScanResult((ScannerResult('http_headers', 'HTTP 200\nServer: ordinary', 'COMPLETE', True),
                             ScannerResult('tls', 'Days remaining: 1', 'FAILED', False)))
        self.assertEqual(scan_report(plan(('4', 'd')), result)['findings'], [])

    def test_nuclei_duplicates_do_not_break_downstream_review_identity(self):
        selected = build_custom_plan('example.test', ('7',), active_consent=True)
        text = 'TEMPLATE sample | high | Example observation | https://example.test\n' * 2
        report = scan_report(selected, ScanResult((ScannerResult('nuclei', text, 'COMPLETE', True),)))
        self.assertEqual(len(report['findings']), 1)

    def test_changing_certificate_countdown_preserves_identity(self):
        selected = plan(('d',))
        def capture(days):
            return scan_report(selected, ScanResult((ScannerResult('tls',
                '[VERIFIED TLS HANDSHAKE] example.test:443\nDays remaining: ' + str(days), 'COMPLETE', True),)))
        self.assertEqual(capture(12)['findings'][0]['fingerprint'], capture(11)['findings'][0]['fingerprint'])
        invalid = ScanResult((ScannerResult('nmap', '99999/tcp open invalid', 'COMPLETE', True),))
        self.assertEqual(scan_report(plan(('1',)), invalid)['findings'], [])


class ReviewBatchTests(unittest.TestCase):
    def test_failed_report_does_not_stop_other_reviews(self):
        from penx_app.application.local_review import main
        with tempfile.TemporaryDirectory() as root:
            good = Path(root) / 'good.json'
            good.write_text('{"schema":"penx-scan-v1"}')
            draft = {'state': 'draft-unverified'}
            with patch('penx_app.application.local_review.create_review', return_value=draft) as review:
                code = main([str(Path(root) / 'missing.json'), str(good), '--model', 'local', '--output', root])
            self.assertEqual(code, 1)
            review.assert_called_once()
            manifest = json.loads((Path(root) / 'penx_review_batch.json').read_text())
            self.assertEqual([row['status'] for row in manifest['outcomes']], ['failed', 'draft'])

    def test_exhausted_batch_never_calls_model(self):
        from penx_app.application.local_review import main
        with tempfile.TemporaryDirectory() as root, \
                patch('penx_app.application.local_review.time.monotonic', side_effect=[0, 601, 602]), \
                patch('penx_app.application.local_review.create_review') as review:
            self.assertEqual(main(['one.json', 'two.json', '--model', 'local', '--output', root]), 1)
            review.assert_not_called()
            manifest = json.loads((Path(root) / 'penx_review_batch.json').read_text())
            self.assertTrue(all(item['status'] == 'failed' for item in manifest['outcomes']))


if __name__ == '__main__':
    unittest.main()
