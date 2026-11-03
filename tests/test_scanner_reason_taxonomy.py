"""PX-002 offline contracts: versioned machine-readable reason codes.

Every terminal adapter outcome must carry a stable reason from the closed
REASON_CODES set, the metadata round-trip must stay backward compatible for
v1/v2 rows, and no FAILED row may claim evidence. All tests are deterministic
and offline (short-lived local Python processes for process-level paths).
"""
from __future__ import annotations

import json
import sys
import threading
import unittest
from unittest.mock import Mock, patch

import requests

from penx_app.domain.scan_models import (
    ScanResult, ScannerOutput, ScannerResult,
)
from penx_app.domain.scan_reasons import (
    REASON_CODES, REASON_VERSION, is_valid_reason,
)
from penx_app.scanners.process_runner import run_tool


def _row(scanner_id: str = 'nmap', status: str = 'FAILED', evidence: bool = False,
         reason: str | None = None) -> ScannerResult:
    return ScannerResult(scanner_id, 'text', status, evidence, 'Nmap',
                         reason=reason)


class ReasonVocabularyTests(unittest.TestCase):
    def test_versioned_closed_set(self):
        self.assertEqual(REASON_VERSION, 1)
        self.assertEqual(set(REASON_CODES), {
            'missing_dependency', 'timeout', 'cancelled', 'truncated',
            'scope_denied', 'parse_invalid', 'partial', 'error', 'skipped'})

    def test_is_valid_reason(self):
        self.assertTrue(is_valid_reason(None))
        for code in REASON_CODES:
            self.assertTrue(is_valid_reason(code), code)
        for bad in ('TIMEOUT', 'timeout ', 'unknown', '', 1, b'timeout'):
            self.assertFalse(is_valid_reason(bad), repr(bad))


class DomainReasonFieldTests(unittest.TestCase):
    def test_result_accepts_known_codes_and_rejects_unknown(self):
        for code in REASON_CODES:
            self.assertEqual(_row(reason=code).reason, code)
        with self.assertRaises(ValueError):
            _row(reason='boom')
        self.assertIsNone(_row().reason)

    def test_failed_row_with_evidence_still_rejected_with_reason(self):
        with self.assertRaises(ValueError):
            _row(status='FAILED', evidence=True, reason='timeout')

    def test_output_validation(self):
        self.assertEqual(ScannerOutput('x', reason='timeout').reason, 'timeout')
        self.assertIsNone(ScannerOutput('x').reason)
        with self.assertRaises(ValueError):
            ScannerOutput('x', reason='nope')


class MetadataRoundTripTests(unittest.TestCase):
    def test_rows_without_reason_stay_legacy_and_lose_nothing(self):
        result = ScanResult((_row('nmap', 'COMPLETE', True),))
        payload = json.loads(result.metadata())
        self.assertEqual(payload['version'], 1)
        self.assertNotIn('reason', payload['adapters'][0])
        restored = ScanResult.from_metadata(result.metadata())
        self.assertIsNone(restored.results[0].reason)
        self.assertEqual(restored.results[0].status, 'COMPLETE')

    def test_reason_round_trips_through_version_3(self):
        result = ScanResult((_row('whois', 'FAILED', False, 'timeout'),))
        payload = json.loads(result.metadata())
        self.assertEqual(payload['version'], 3)
        self.assertEqual(payload['adapters'][0]['reason'], 'timeout')
        restored = ScanResult.from_metadata(result.metadata())
        self.assertEqual(restored.results[0].reason, 'timeout')
        self.assertEqual(restored.results[0].status, 'FAILED')
        self.assertFalse(restored.results[0].evidence)

    def test_version_3_without_reason_restores_none(self):
        row = {'id': 'nmap', 'name': 'Nmap', 'status': 'PARTIAL',
               'evidence': False, 'events': []}
        text = json.dumps({'version': 3, 'adapters': [row]})
        restored = ScanResult.from_metadata(text)
        self.assertIsNone(restored.results[0].reason)

    def test_reason_is_only_valid_in_version_3(self):
        row = {'id': 'nmap', 'name': 'Nmap', 'status': 'FAILED',
               'evidence': False, 'reason': 'timeout'}
        for version in (1, 2):
            text = json.dumps({'version': version, 'adapters': [dict(row)]})
            with self.subTest(version=version):
                with self.assertRaises(ValueError):
                    ScanResult.from_metadata(text)

    def test_unknown_or_null_reason_codes(self):
        base = {'id': 'nmap', 'name': 'Nmap', 'status': 'FAILED',
                'evidence': False, 'events': []}
        with self.assertRaises(ValueError):
            ScanResult.from_metadata(json.dumps({
                'version': 3, 'adapters': [dict(base, reason='boom')]}))
        restored = ScanResult.from_metadata(json.dumps({
            'version': 3, 'adapters': [dict(base, reason=None)]}))
        self.assertIsNone(restored.results[0].reason)


class ProcessRunnerReasonTests(unittest.TestCase):
    def python(self, code: str, timeout: int = 5) -> ScannerOutput:
        return run_tool([sys.executable, '-c', code], timeout=timeout)

    def test_success_has_no_reason(self):
        result = self.python("print('ok')")
        self.assertEqual(result.status, 'COMPLETE')
        self.assertIsNone(result.reason)

    def test_nonzero_exit_is_error(self):
        result = self.python("import sys; sys.exit(3)")
        self.assertEqual(result.status, 'FAILED')
        self.assertEqual(result.reason, 'error')

    def test_timeout_is_timeout(self):
        result = self.python('import time; time.sleep(3)', timeout=1)
        self.assertEqual(result.status, 'PARTIAL')
        self.assertEqual(result.reason, 'timeout')

    def test_invalid_utf8_is_parse_invalid(self):
        result = self.python(
            "import sys; sys.stdout.buffer.write(b'ok\\xff\\x00\\n')")
        self.assertEqual(result.status, 'PARTIAL')
        self.assertEqual(result.reason, 'parse_invalid')

    def test_missing_executable_is_missing_dependency(self):
        result = run_tool(['/nonexistent-scanner-binary-xyz', 'target'])
        self.assertEqual(result.status, 'FAILED')
        self.assertEqual(result.reason, 'missing_dependency')

    def test_precancelled_request_is_cancelled(self):
        event = threading.Event()
        event.set()
        result = run_tool([sys.executable, '-c', 'print(1)'],
                          cancel_event=event)
        self.assertEqual(result.status, 'PARTIAL')
        self.assertFalse(result.evidence)
        self.assertEqual(result.reason, 'cancelled')


class AdapterReasonMatrixTests(unittest.TestCase):
    """Every terminal adapter outcome reports a stable reason code."""

    def test_every_adapter_reports_cancelled_before_start(self):
        from penx_app.scanners.tools import TOOLS_MENU
        for key, (name, runner) in TOOLS_MENU.items():
            with self.subTest(adapter=key):
                event = threading.Event()
                event.set()
                result = runner('example.test', cancel_event=event)
                self.assertIsInstance(result, ScannerOutput, name)
                self.assertEqual(result.status, 'PARTIAL', name)
                self.assertFalse(result.evidence, name)
                self.assertEqual(result.reason, 'cancelled', name)

    def test_missing_dependencies(self):
        from penx_app.scanners import tools
        cases = {
            'nmap': lambda: patch.object(tools, '_executable',
                                         return_value=None),
            'nikto': lambda: patch.object(tools, '_executable',
                                          return_value=None),
            'nuclei': lambda: patch.object(tools, 'find_native',
                                           return_value=None),
            'httpx': lambda: patch.object(tools, 'find_native',
                                          return_value=None),
            'ffuf': lambda: patch.object(tools, 'find_native',
                                         return_value=None),
            'endpoint_mapping': lambda: patch.object(tools, 'find_native',
                                                     return_value=None),
            'subfinder': lambda: patch.object(tools, 'find_native',
                                              return_value=None),
            'katana': lambda: patch.object(tools, 'find_native',
                                           return_value=None),
        }
        with patch.object(tools, 'NIKTO_PATH', ''), \
             patch.object(tools, 'NMAP_PATH', ''):
            for adapter, case in cases.items():
                with self.subTest(adapter=adapter):
                    with case():
                        result = TOOLS_RUNNERS[adapter]('example.test')
                        self.assertEqual(result.status, 'FAILED', adapter)
                        self.assertEqual(result.reason, 'missing_dependency',
                                         adapter)
        with patch.dict(sys.modules, {'whois': None}):
            self.assertEqual(tools.run_whois('example.test').reason,
                             'missing_dependency')
        with patch.dict(sys.modules, {'dns': None, 'dns.resolver': None,
                                      'dns.exception': None}):
            self.assertEqual(tools.run_dig('example.test').reason,
                             'missing_dependency')

    def test_scope_denied_targets(self):
        from penx_app.scanners import tools
        self.assertEqual(tools.run_whois('192.0.2.1').reason, 'scope_denied')
        self.assertEqual(tools.run_dig('192.0.2.0/24').reason, 'scope_denied')
        self.assertEqual(tools.run_subfinder('192.0.2.1').reason,
                         'scope_denied')

    def test_adapter_errors(self):
        from penx_app.scanners import tools
        with patch('socket.create_connection',
                   side_effect=ConnectionError('offline')):
            self.assertEqual(tools.run_tls_check('example.test').reason,
                             'error')
        with patch('penx_app.scanners.tools._urls',
                   return_value=['https://example.test']), \
             patch('penx_app.scanners.tools.requests.head',
                   side_effect=requests.ConnectionError('offline')):
            self.assertEqual(tools.run_curl_headers('example.test').reason,
                             'error')

    def test_http_headers_partial_reports_partial(self):
        from penx_app.scanners import tools
        response = requests.models.Response()
        response.status_code = 200
        response.url = 'https://example.test'
        response.headers = {'Server': 'fixture'}
        response.raw = Mock()
        with patch('penx_app.scanners.tools._urls', return_value=[
                'https://example.test', 'http://example.test']), \
             patch('penx_app.scanners.tools.requests.head',
                   side_effect=[response, requests.ConnectionError('offline')]):
            result = tools.run_curl_headers('example.test')
        self.assertEqual(result.status, 'PARTIAL')
        self.assertEqual(result.reason, 'partial')

    def test_discovery_parse_invalid(self):
        from penx_app.scanners import tools
        output = ScannerOutput('{"host":"bad@.x"}\nnot-json\n',
                               status='COMPLETE', evidence=True)
        with patch.object(tools, 'find_native', return_value='/subfinder'), \
             patch.object(tools, '_run_external', return_value=output):
            result = tools.run_subfinder('example.test')
        self.assertEqual(result.status, 'FAILED')
        self.assertEqual(result.reason, 'parse_invalid')
        output = ScannerOutput(
            '{"request":{"endpoint":"https://example.test/ok"}}\ngarbage\n',
            status='COMPLETE', evidence=True)
        with patch.object(tools, 'find_native', return_value='/katana'), \
             patch.object(tools, '_run_external', return_value=output):
            result = tools.run_katana('example.test')
        self.assertEqual(result.status, 'PARTIAL')
        self.assertTrue(result.evidence)
        self.assertEqual(result.reason, 'parse_invalid')


class ExecutionReasonTests(unittest.TestCase):
    def test_execution_helper_rows(self):
        from penx_app.application import scanner_execution as execution
        _, row = execution._cancelled_row('Nmap', '1')
        self.assertEqual(row.reason, 'cancelled')
        _, row = execution._overload_skip_row('Nikto', '6')
        self.assertEqual(row.reason, 'skipped')

    def test_adapter_exception_and_legacy_text(self):
        from penx_app.application import scanner_execution as execution
        def boom(target):
            raise RuntimeError('adapter crash')

        row = execution._run_adapter('Nmap', boom, 'example.test',
                                     lambda *_: None, None, '1')
        self.assertEqual(row.reason, 'error')
        row = execution._run_adapter('Nmap', lambda t: '[!] crashed',
                                     'example.test', lambda *_: None, None, '1')
        self.assertEqual(row.reason, 'error')
        row = execution._run_adapter('Nmap', lambda t: 42, 'example.test',
                                     lambda *_: None, None, '1')
        self.assertEqual(row.reason, 'error')
        row = execution._run_adapter('Nmap', lambda t: 'plain legacy text',
                                     'example.test', lambda *_: None, None, '1')
        self.assertIsNone(row.reason)

    def test_selected_run_cancels_before_start(self):
        from penx_app.application import scanner_execution as execution
        from penx_app.domain.scan_models import ScanRequest
        request = ScanRequest('example.test', ('1',), False)
        menu = {'1': ('Nmap', lambda target: ScannerOutput('never ran'))}
        event = threading.Event()
        event.set()
        rendered = execution.run_selected(
            request, menu=menu, emit=lambda *_: None, cancel_event=event)
        self.assertEqual(rendered['Nmap'].reason, 'cancelled')

    def test_terminal_event_prefers_machine_reason(self):
        from penx_app.application import scan_planner
        self.assertEqual(scan_planner._terminal_event(
            ScannerOutput('x', status='PARTIAL', evidence=False,
                          reason='cancelled')), 'cancelled')
        self.assertEqual(scan_planner._terminal_event(
            ScannerOutput('x', status='PARTIAL', evidence=False,
                          reason='skipped')), 'skipped')
        self.assertEqual(scan_planner._terminal_event(
            ScannerOutput('x', status='PARTIAL', evidence=False,
                          reason='timeout')), 'partial')
        self.assertEqual(scan_planner._terminal_event(
            ScannerOutput('x', status='PARTIAL', evidence=False,
                          diagnostics='Caller cancelled the scan')),
            'cancelled')


class PassiveReasonTests(unittest.TestCase):
    def _plan(self):
        from penx_app.domain.scan_plan import ScanPlan
        return ScanPlan('passive', 1, 'example.test', (), True, False,
                        {}, 1, 30, None)

    def test_precancelled_passive_run(self):
        from penx_app.application.passive_execution import run_passive_plan
        event = threading.Event()
        event.set()
        result = run_passive_plan(self._plan(), cancel_event=event)
        self.assertTrue(result.results)
        for row in result.results:
            self.assertEqual(row.status, 'PARTIAL')
            self.assertFalse(row.evidence)
            self.assertEqual(row.reason, 'cancelled')

    def test_budget_exhausted_is_timeout(self):
        from penx_app.application.passive_execution import run_passive_plan
        calls = {'n': 0}

        def clock():
            calls['n'] += 1
            return 131.0 if calls['n'] >= 5 else 100.0

        result = run_passive_plan(self._plan(), clock=clock)
        self.assertTrue(result.results)
        for row in result.results:
            self.assertEqual(row.status, 'PARTIAL')
            self.assertEqual(row.reason, 'timeout')

    def test_clipped_provider_output_is_truncated(self):
        from penx_app.application.passive_execution import run_passive_plan
        long_records = ['x' * 350 for _ in range(15)]
        def fake_query(url, **kwargs):
            if 'crt.sh' in url:
                return [{'name_value': 'example.test'}]
            return {'name': 'example.test'}
        with patch('dns.resolver.resolve', return_value=long_records), \
             patch('penx_app.application.passive_execution._query_json',
                   side_effect=fake_query):
            result = run_passive_plan(self._plan())
        dns_row = next(row for row in result.results
                       if row.scanner_id == 'passive_dns')
        self.assertEqual(dns_row.status, 'PARTIAL')
        self.assertEqual(dns_row.reason, 'truncated')
        ct_row = next(row for row in result.results
                      if row.scanner_id == 'passive_ct')
        self.assertEqual(ct_row.status, 'COMPLETE')
        self.assertIsNone(ct_row.reason)


class ReportReasonTests(unittest.TestCase):
    def _report(self, reason: str | None = 'timeout',
                status: str = 'FAILED') -> dict:
        from penx_app.application.scan_profiles import build_custom_plan
        from penx_app.application.headless_scan import scan_report
        plan = build_custom_plan('example.test', ('7',), active_consent=True)
        result = ScanResult((
            ScannerResult('nuclei', 'sample | high | note | url',
                          status, status != 'FAILED', 'Nuclei',
                          reason=reason),
        ))
        return scan_report(plan, result)

    def test_headless_report_carries_reason(self):
        report = self._report()
        self.assertEqual(report['adapters'][0]['reason'], 'timeout')
        report = self._report(reason=None, status='COMPLETE')
        self.assertIsNone(report['adapters'][0]['reason'])

    def test_sarif_notifications_include_reason(self):
        from penx_app.reporting.machine_reports import sarif_from_report
        report = self._report()
        payload = sarif_from_report(report)
        notifications = payload['runs'][0]['invocations'][
            0]['toolExecutionNotifications']
        self.assertEqual(len(notifications), 1)
        self.assertEqual(notifications[0]['properties']['reason'], 'timeout')
        report = self._report(reason=None, status='COMPLETE')
        payload = sarif_from_report(report)
        notifications = payload['runs'][0]['invocations'][
            0]['toolExecutionNotifications']
        self.assertEqual(notifications, [])


class LLMBoundaryReasonTests(unittest.TestCase):
    def test_reason_survives_the_llm_text_boundary(self):
        from penx_app.scanners.scan_results import format_recon_for_llm
        result = ScanResult((
            ScannerResult('nmap', '80/tcp open', 'PARTIAL', True, 'Nmap',
                          reason='truncated'),
        ))
        formatted = format_recon_for_llm(result)
        self.assertIsInstance(formatted, str)
        # The text marker stays stable; the typed result carries the reason.
        self.assertIn('[PENX ADAPTER STATUS: PARTIAL; EVIDENCE: YES]',
                      formatted)
        self.assertEqual(formatted.result.results[0].reason, 'truncated')
        # Legacy dict/ScannerOutput input keeps working and carries reason.
        from penx_app.scanners.scan_results import recon_has_evidence
        text = format_recon_for_llm({'nmap': ScannerOutput(
            '80/tcp open', status='COMPLETE', reason='timeout')})
        self.assertTrue(recon_has_evidence(text))
        self.assertEqual(text.result.results[0].reason, 'timeout')


TOOLS_RUNNERS = {}  # filled below once tools import is available


def _load_runners() -> None:
    from penx_app.scanners.tools import TOOLS_MENU
    mapping = {
        'nmap': '1', 'nikto': '6', 'nuclei': '7', 'httpx': '8',
        'ffuf': '9', 'endpoint_mapping': 'e', 'subfinder': 's',
        'katana': 'c',
    }
    for label, key in mapping.items():
        TOOLS_RUNNERS[label] = TOOLS_MENU[key][1]


_load_runners()


if __name__ == '__main__':
    unittest.main()
