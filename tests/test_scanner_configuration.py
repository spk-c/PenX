"""Typed options, profile boundaries and parallel cancellation, all offline."""
from dataclasses import replace
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from penx_app.application.profile_documents import ProfileDocument, builtin_document, load_profile
from penx_app.application.scan_planner import run_plan
from penx_app.application.scan_profiles import build_custom_plan
from penx_app.application.scan_trends import compare_sessions
from penx_app.domain.scan_models import ScannerOutput, ScanResult
from penx_app.domain.scanner_configuration import ScannerConfiguration as Config
from penx_app.scanners.configuration_runtime import configured_adapter, external_options


class ScannerConfigurationTests(unittest.TestCase):
    def test_timeout_for_every_registry_scanner(self):
        for key in ('1', '2', '3', '4', '5', '6', '7', '8', '9', 'e', 's', 'c', 'd'):
            for timeout in (30, 900):
                self.assertEqual(Config.from_dict(Config(key, timeout).to_dict()), Config(key, timeout))
        for value in (True, 29, 901, '60'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                Config('1', value)

    def test_allowlists_reject_flags_paths_secrets_and_expanded_rates(self):
        for field in ('args', 'shell', 'target', 'api_key', 'headers', 'template_path', 'env', 'consent'):
            with self.subTest(field=field), self.assertRaises(ValueError):
                Config.from_dict({'scanner_key': '7', field: 'injected'})
        for values in (dict(scanner_key='1', ports=('--script',)),
                       dict(scanner_key='1', ports=(True,)),
                       dict(scanner_key='4', ports=(80,)),
                       dict(scanner_key='7', severities=('info',)),
                       dict(scanner_key='7', rate_limit=3),
                       dict(scanner_key='8', rate_limit=4),
                       dict(scanner_key='9', rate_limit=True)):
            with self.subTest(values=values), self.assertRaises(ValueError):
                Config(**values)

    def test_command_changes_are_fixed_list_arguments_and_context_is_reset(self):
        with configured_adapter(Config('1', 60, ports=(80, 443))):
            args, timeout = external_options(['nmap', '-sV', 'example.test'], 180)
            self.assertEqual(args, ['nmap', '-p', '80,443', '-sV', 'example.test'])
            self.assertEqual(timeout, 60)
        self.assertEqual(external_options(['nmap'], 180), (['nmap'], 180))
        with configured_adapter(Config('7', severities=('high',), rate_limit=1)):
            args, _ = external_options(['nuclei', '-severity', 'low,medium,high,critical', '-rl', '2', '-ni'], 240)
            self.assertEqual(args, ['nuclei', '-severity', 'high', '-rl', '1', '-ni'])

    def test_plan_applies_options_inside_each_worker_without_env_mutation(self):
        barrier = threading.Barrier(2)
        commands = {}
        def runner(key, command):
            def run(target, *, cancel_event=None):
                barrier.wait(timeout=2)
                commands[key] = external_options(command + [target], 180)
                return ScannerOutput('Observed test output')
            return run
        plan = replace(build_custom_plan('example.test', ('1', '2'), active_consent=False, max_parallelism=2),
                       scanner_configuration=(Config('1', 60, ports=(443,)), Config('2', 90)))
        result = run_plan(plan, menu={'1': ('Nmap', runner('1', ['nmap'])), '2': ('Whois', runner('2', ['whois']))})
        self.assertEqual(commands['1'], (['nmap', '-p', '443', 'example.test'], 60))
        self.assertEqual(commands['2'], (['whois', 'example.test'], 90))
        restored = ScanResult.from_metadata(result.metadata())
        self.assertEqual(restored.scanner_configuration, plan.scanner_configuration)

    def test_adapter_process_receives_typed_timeout_and_ports(self):
        from penx_app.scanners import tools
        plan = replace(build_custom_plan('example.test', ('1',), active_consent=False),
                       scanner_configuration=(Config('1', 60, ports=(443,)),))
        def runner(target):
            return tools._run_external(['nmap', target], timeout=180)
        with patch.object(tools, 'run_tool', return_value=ScannerOutput('Observed output')) as process:
            run_plan(plan, menu={'1': ('Nmap', runner)})
        self.assertEqual(process.call_args.args[0], ['nmap', '-p', '443', 'example.test'])
        self.assertEqual(process.call_args.kwargs['timeout'], 60)

    def test_node_timeout_signals_worker_and_retains_parallelism(self):
        active = 0
        peak = 0
        def runner(target, *, cancel_event=None):
            nonlocal active, peak
            active += 1
            peak = max(peak, active)
            self.assertTrue(cancel_event.wait(1), 'node deadline must signal its worker')
            active -= 1
            return ScannerOutput('Late output must not replace timed-out result')
        plan = build_custom_plan('example.test', ('1', '2'), active_consent=False, global_budget_seconds=30)
        with patch('penx_app.application.scan_planner.resolve_node_timeout', return_value=0.05):
            result = run_plan(plan, menu={'1': ('Nmap', runner), '2': ('Whois', runner)})
        self.assertEqual(peak, 1)
        self.assertTrue(all(row.status == 'PARTIAL' and not row.evidence for row in result.results))

    def test_global_budget_cancels_even_when_every_node_has_started(self):
        def runner(target, *, cancel_event=None):
            self.assertTrue(cancel_event.wait(1000))
            return ScannerOutput('Cancelled', status='PARTIAL', evidence=False)
        plan = build_custom_plan('example.test', ('1',), active_consent=False, global_budget_seconds=30)
        # Only execution clock advances; validation retains its real 30s minimum.
        start = time.monotonic()
        original = time.monotonic
        def accelerated():
            return start + (original() - start) * 1000
        with patch('penx_app.application.scan_planner.time.monotonic', side_effect=accelerated):
            result = run_plan(plan, menu={'1': ('Nmap', runner)})
        self.assertEqual(result.results[0].status, 'PARTIAL')

    def test_invalid_selection_configuration_fails_before_any_adapter(self):
        plan = replace(build_custom_plan('example.test', ('1',), active_consent=False),
                       scanner_configuration=(Config('7'),))
        with patch('penx_app.application.scan_planner._run_adapter') as run, self.assertRaises(ValueError):
            run_plan(plan, menu={})
        run.assert_not_called()

    def test_profile_round_trip_carries_no_scope_or_consent(self):
        document = ProfileDocument('my_web', 2, ('7',), scanner_configuration=(Config('7', 60, severities=('high',), rate_limit=1),))
        restored = ProfileDocument.from_dict(document.to_dict())
        self.assertEqual(restored, document)
        with self.assertRaises(ValueError):
            restored.to_plan('example.test', active_consent=False)
        self.assertEqual(restored.to_plan('example.test', active_consent=True).per_scanner_timeouts, {'7': 60})
        for field in ('target', 'active_consent', 'password', 'api_key'):
            with self.subTest(field=field), self.assertRaises(ValueError):
                ProfileDocument.from_dict(dict(document.to_dict(), **{field: 'forbidden'}))

    def test_profile_size_duplicates_and_bounds(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'profile.json'
            for text in (' ' * 65537, '{"profile_id":"one","profile_id":"two"}'):
                path.write_text(text)
                with self.assertRaises(ValueError):
                    load_profile(path)
            for changes in ({'max_parallelism': 9}, {'global_budget_seconds': 3601},
                            {'profile_version': True}, {'schema_version': True},
                            {'scanner_configuration': [{'scanner_key': '1', 'timeout_seconds': True}]}):
                payload = dict(builtin_document('standard').to_dict(), **changes)
                path.write_text(json.dumps(payload))
                with self.subTest(changes=changes), self.assertRaises(ValueError):
                    load_profile(path)

    def test_builtin_export_import_and_headless_selection(self):
        from penx_app.application.profile_documents import main
        from penx_app.application.headless_scan import main as scan
        with tempfile.TemporaryDirectory() as root:
            self.assertEqual(main(['--export', 'standard', '--output', root]), 0)
            path = Path(root) / 'standard.profile.json'
            self.assertEqual(main(['--validate', str(path)]), 0)
            self.assertEqual(main(['--copy', str(path), '--output', root]), 0)
            self.assertEqual(load_profile(Path(root) / 'standard_1.profile.json'), load_profile(path))
            with patch('penx_app.application.headless_scan.build_preflight') as preflight, \
                    patch('penx_app.application.headless_scan.format_report', return_value='dry run'):
                preflight.return_value.available = True
                self.assertEqual(scan(['--target', 'example.test', '--profile-file', str(path), '--dry-run']), 0)
                self.assertEqual(preflight.call_args.args[0].profile_id, 'standard')

    def test_configuration_differences_are_visible_in_comparisons(self):
        from penx_app.domain.scan_diagnostics import PlanSummary
        from penx_app.domain.scan_models import ScannerResult
        def session(number, ports):
            return {'history': (number, 'example.test', '2026-10-22', 'active'),
                    'summary': (1, number, '', '', 'LOW'), 'vulns': [], 'corrections': [],
                    'scan_result': ScanResult((ScannerResult('nmap', '', 'COMPLETE', True, 'NMAP'),),
                                              PlanSummary('custom', 1, 1, None), (Config('1', ports=ports),))}
        diff = compare_sessions(session(1, (80,)), session(2, (443,)))
        self.assertTrue(any('configuration differ' in note for note in diff['comparability_notes']))


if __name__ == '__main__':
    unittest.main()
