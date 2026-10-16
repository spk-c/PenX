"""Offline regressions for Issue #53: evidence, DB layouts, targets and streams."""
import os
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

STORAGE = tempfile.TemporaryDirectory(prefix='penx_audit_db_')
os.environ['PENX_DB_ENGINE'] = 'sqlite'
os.environ['PENX_DB_PATH'] = str(Path(STORAGE.name) / 'fresh.sqlite')

from penx_app.scanners import tools
from penx_app.storage import db
from penx_app.storage import db_backend
from penx_app.analysis.llm_client import complete_chat, EmptyModelResponse
from penx_app.application.scan_trends import compare_sessions
from penx_app.reporting.export import fetch_session, export_html
from penx_app.storage.db_evals import export_eval_package
from penx_app.storage.db_training import export_training_data


class AuditRegressions(unittest.TestCase):
    def test_failed_http_adapter_is_not_evidence(self):
        with patch('penx_app.scanners.tools.requests.head', side_effect=tools.requests.ConnectionError('offline fixture')):
            raw = tools.format_recon_for_llm({'HTTP headers': tools.run_curl_headers('example.test')})
        self.assertFalse(tools.recon_has_evidence(raw), raw)

    def test_unavailable_passive_dns_is_not_evidence(self):
        import dns.resolver
        from penx_app.scanners.passive_recon import _dns_lookup
        with patch('dns.resolver.resolve', side_effect=dns.resolver.NXDOMAIN()):
            raw = '[DNS VIA RESOLVER]\n' + _dns_lookup('example.test')
        self.assertFalse(tools.recon_has_evidence(raw, passive_only=True), raw)

    def test_bare_web_target_keeps_explicit_port(self):
        self.assertEqual(tools._urls('example.test:8443'),
                         ['https://example.test:8443', 'http://example.test:8443'])
        self.assertEqual(tools._web_target('example.test:8443'), 'example.test:8443')

    def test_legacy_migration_preserves_public_row_layout(self):
        path = Path(STORAGE.name) / 'legacy.sqlite'
        conn = sqlite3.connect(path)
        conn.executescript('''
            CREATE TABLE history (sl_no INTEGER PRIMARY KEY, target TEXT, scan_date TEXT, status TEXT);
            CREATE TABLE vulnerabilities (id INTEGER PRIMARY KEY, sl_no INTEGER, vuln_name TEXT,
                severity TEXT, port TEXT, service TEXT, description TEXT);
            CREATE TABLE summary (id INTEGER PRIMARY KEY, sl_no INTEGER, raw_scan TEXT,
                ai_analysis TEXT, risk_level TEXT, generated_at TEXT);
            INSERT INTO history VALUES (1, 'example.test', '2026-01-01', 'active');
            INSERT INTO vulnerabilities VALUES (1, 1, 'Example', 'high', '443', 'https', 'Original evidence');
            INSERT INTO summary VALUES (1, 1, 'scan', 'analysis', 'HIGH', '2026-01-01');
        ''')
        conn.close()
        with patch.object(db_backend, 'DB_PATH', str(path)):
            record = db.get_session(1)
            # Reopening after migration (user_version=1) must also work.
            self.assertEqual(fetch_session(1)['vulns'], record['vulns'])
            self.assertEqual(fetch_session(1)['summary'], record['summary'])
            self.assertEqual(db.get_vulnerabilities(1), record['vulns'])
            new_id = db.save_vulnerability(1, 'New finding', 'low', '8080', 'http', 'New evidence')
            self.assertEqual(db.get_vulnerabilities(1)[-1][4:],
                             ('possible', '8080', 'http', 'New evidence'))
            db.save_correction(1, new_id, 'verified', '', '', 'Fixture review')
            exported = export_training_data(STORAGE.name)
            training = json.loads(Path(exported).read_text(encoding='utf-8').splitlines()[0])
            answer = next(m['content'] for m in training['messages'] if m['role'] == 'assistant')
            self.assertIn('PORT: 8080 | SERVICE: http', answer)
            self.assertIn('DESC: New evidence', answer)
            self.assertNotIn('PORT: 443 | SERVICE: https', answer)
            package = Path(export_eval_package(1, STORAGE.name)).read_text(encoding='utf-8')
            self.assertIn('**Port:** 443', package)
            self.assertIn('**Description:** Original evidence', package)
            html = Path(export_html(fetch_session(1), STORAGE.name)).read_text(encoding='utf-8')
            self.assertIn('Original evidence', html)
            self.assertIn('Port: 443', html)
        self.assertEqual(record['vulns'][0][4:],
                         ('possible', '443', 'https', 'Original evidence'))
        self.assertEqual(record['summary'][5:], ('', '2026-01-01'))

    def test_stream_without_completion_is_rejected(self):
        response = MagicMock()
        response.__enter__.return_value = response
        response.headers = {'content-type': 'text/event-stream'}
        response.iter_lines.return_value = iter([
            'data: {"choices":[{"delta":{"content":"RISK_LEVEL: HIGH\\nSUMMARY: partial"},"finish_reason":null}]}',
            '',
        ])
        with patch('penx_app.analysis.llm_client.requests.post', return_value=response):
            with self.assertRaises(EmptyModelResponse):
                complete_chat([], url='http://localhost/v1/chat/completions',
                              models_url='http://localhost/v1/models', model_name='fixture',
                              stream_callback=lambda _: None)

    def test_subnet_host_order_does_not_change_services(self):
        def host(address, product):
            return (f'<host><address addr="{address}" addrtype="ipv4"/><ports>'
                    '<port protocol="tcp" portid="80"><state state="open"/>'
                    f'<service name="http" product="{product}" version="1.0"/>'
                    '</port></ports></host>')
        a, b = host('192.0.2.1', 'nginx'), host('192.0.2.2', 'Apache')
        def session(index, hosts):
            xml = '<nmaprun>' + hosts + '<runstats><finished exit="success"/></runstats></nmaprun>'
            return {'history': (index, '192.0.2.0/24', '2026-01-01', 'active'),
                    'summary': (index, index, xml, '', 'LOW', '', ''), 'vulns': []}
        diff = compare_sessions(session(1, a+b), session(2, b+a))
        self.assertTrue(diff['port_comparison_reliable'])
        self.assertEqual(diff['service_changes'], [])


class AuditControls(unittest.TestCase):
    def test_successful_http_is_evidence(self):
        response = MagicMock(status_code=200, url='https://example.test')
        response.headers = {'Server': 'fixture'}
        with patch('penx_app.scanners.tools.requests.head', return_value=response):
            raw = tools.format_recon_for_llm({'HTTP headers': tools.run_curl_headers('example.test')})
        self.assertTrue(tools.recon_has_evidence(raw))

    def test_successful_passive_dns_is_evidence(self):
        self.assertTrue(tools.recon_has_evidence(
            '[DNS VIA RESOLVER]\nA: 192.0.2.1', passive_only=True))

    def test_explicit_url_keeps_port(self):
        url = 'https://example.test:8443/'
        self.assertEqual(tools._urls(url), [url])
        self.assertEqual(tools._web_target(url), url)

    def test_fresh_database_has_expected_layout(self):
        ident = db.create_session('example.test')
        db.save_vulnerability(ident, 'Example', 'high', '443', 'https', 'Original evidence')
        self.assertEqual(db.get_session(ident)['vulns'][0][4:],
                         ('possible', '443', 'https', 'Original evidence'))

    def test_completed_stream_is_accepted(self):
        response = MagicMock()
        response.__enter__.return_value = response
        response.headers = {'content-type': 'text/event-stream'}
        response.iter_lines.return_value = iter([
            'data: {"choices":[{"delta":{"content":"complete"},"finish_reason":null}]}', '',
            'data: {"choices":[{"delta":{},"finish_reason":"stop"}]}', '',
            'data: [DONE]', '',
        ])
        with patch('penx_app.analysis.llm_client.requests.post', return_value=response):
            result = complete_chat([], url='http://localhost/v1/chat/completions',
                                   models_url='http://localhost/v1/models', model_name='fixture',
                                   stream_callback=lambda _: None)
        self.assertEqual(result, ('fixture', 'complete'))


class AdapterEdgeCases(unittest.TestCase):
    def test_failed_http_with_uppercase_scheme_is_not_evidence(self):
        for target in ('HTTPS://example.test', 'Http://example.test'):
            with self.subTest(target=target), \
                 patch('penx_app.scanners.tools.requests.head', side_effect=tools.requests.ConnectionError('offline')):
                raw = tools.format_recon_for_llm({'HTTP headers': tools.run_curl_headers(target)})
                self.assertFalse(tools.recon_has_evidence(raw))

    def test_uppercase_scheme_fingerprint_success_is_evidence(self):
        response = MagicMock(status_code=200, url='https://example.test', encoding='utf-8')
        response.headers = {'Server': 'fixture'}
        response.raw.read.return_value = b'<html>fixture</html>'
        with patch.object(tools, 'WHATWEB_PATH', ''), \
             patch('penx_app.scanners.tools._executable', return_value=None), \
             patch('penx_app.scanners.tools.requests.get', return_value=response):
            raw = tools.run_whatweb('HTTPS://example.test')
        self.assertTrue(tools.recon_has_evidence(raw))

    def test_partial_http_and_head_fallback_preserve_evidence(self):
        response = MagicMock(status_code=200, url='http://example.test:8443')
        response.headers = {'Server': 'fixture'}
        with patch('penx_app.scanners.tools.requests.head', side_effect=[
                tools.requests.ConnectionError('offline'), MagicMock(status_code=405)]) as head, \
             patch('penx_app.scanners.tools.requests.get', return_value=response) as get:
            raw = tools.run_curl_headers('example.test:8443')
        self.assertEqual([c.args[0] for c in head.call_args_list],
                         ['https://example.test:8443', 'http://example.test:8443'])
        self.assertEqual(get.call_args.args[0], 'http://example.test:8443')
        self.assertTrue(tools.recon_has_evidence(tools.format_recon_for_llm({'HTTP headers': raw})))

    def test_fingerprint_banner_is_not_evidence(self):
        with patch.object(tools, 'WHATWEB_PATH', ''), \
             patch('penx_app.scanners.tools._executable', return_value=None), \
             patch('penx_app.scanners.tools.requests.get', side_effect=tools.requests.ConnectionError('offline')):
            raw = tools.run_whatweb('example.test')
        self.assertFalse(tools.recon_has_evidence(raw))

    def test_failed_native_dns_is_not_evidence(self):
        import dns.exception
        with patch('dns.resolver.resolve', side_effect=dns.exception.Timeout()):
            raw = tools.run_dig('example.test')
        self.assertFalse(tools.recon_has_evidence(raw))

    def test_passive_dns_empty_and_mixed_results(self):
        for value in ('', '   ', ' unavailable (Timeout)', '\tunavailable (NXDOMAIN)', ' no records'):
            with self.subTest(value=value):
                self.assertFalse(tools.recon_has_evidence(
                    '[DNS VIA RESOLVER]\nA:' + value, passive_only=True))
        self.assertTrue(tools.recon_has_evidence(
            '[DNS VIA RESOLVER]\nA: unavailable (Timeout)\nAAAA: 2001:db8::1', passive_only=True))

    def test_ipv6_web_targets_and_invalid_ports(self):
        for target, authority in (
            ('[2001:db8::1]:8443', '[2001:db8::1]:8443'),
            ('2001:db8::1', '[2001:db8::1]'),
            ('[::1]', '[::1]'), ('192.0.2.1:8080', '192.0.2.1:8080'),
        ):
            with self.subTest(target=target):
                self.assertEqual(tools._web_target(target), authority)
                self.assertEqual(tools._urls(target), ['https://' + authority, 'http://' + authority])
        for target in ('example.test:', 'example.test:no', 'example.test:65536',
                       'example.test:0', '[::1]:-1', 'https://example.test:65536'):
            with self.subTest(target=target):
                with self.assertRaises(ValueError):
                    tools._urls(target)


class StreamingEdgeCases(unittest.TestCase):
    def stream(self, ending):
        response = MagicMock()
        response.__enter__.return_value = response
        response.headers = {'content-type': 'text/event-stream'}
        response.iter_lines.return_value = iter([
            'data: {"choices":[{"delta":{"content":"fixture"}}]}', '', *ending])
        with patch('penx_app.analysis.llm_client.requests.post', return_value=response):
            return complete_chat([], url='http://localhost/v1/chat/completions',
                                 models_url='http://localhost/v1/models', model_name='fixture',
                                 stream_callback=lambda _: None)

    def test_done_only_and_stop_only_are_supported(self):
        self.assertEqual(self.stream(['data: [DONE]', '']), ('fixture', 'fixture'))
        self.assertEqual(self.stream([
            'data: {"choices":[{"delta":{},"finish_reason":"stop"}]}']),
            ('fixture', 'fixture'))

    def test_failure_reason_is_not_overridden_by_done(self):
        for reason in ('length', 'content_filter', 'error'):
            with self.subTest(reason=reason), self.assertRaises(EmptyModelResponse):
                self.stream(['data: ' + json.dumps({'choices': [
                    {'delta': {}, 'finish_reason': reason}]}), '', 'data: [DONE]', ''])

    def test_malformed_terminal_event_does_not_complete_stream(self):
        with self.assertRaises(EmptyModelResponse):
            self.stream(['data: {broken-json', ''])

    def test_error_events_cannot_be_completed_by_done_or_stop(self):
        for error in (
            ['data: {"error":{"message":"backend failed"}}', ''],
            ['event: error', 'data: {"message":"backend failed"}', ''],
        ):
            for ending in (
                ['data: [DONE]', ''],
                ['data: {"choices":[{"delta":{},"finish_reason":"stop"}]}', ''],
            ):
                with self.subTest(error=error, ending=ending), self.assertRaises(EmptyModelResponse):
                    self.stream(error + ending)


class SubnetEdgeCases(unittest.TestCase):
    @staticmethod
    def host(address, product='nginx'):
        addr = f'<address addr="{address}" addrtype="ipv4"/>' if address else ''
        return (f'<host>{addr}<ports><port protocol="tcp" portid="80">'
                f'<state state="open"/><service name="http" product="{product}"/>'
                '</port></ports></host>')

    @staticmethod
    def session(index, hosts, target='192.0.2.0/24'):
        xml = '<nmaprun>' + hosts + '<runstats><finished exit="success"/></runstats></nmaprun>'
        return {'history': (index, target, '2026-01-01', 'active'),
                'summary': (index, index, xml, '', 'LOW'), 'vulns': []}

    def test_shared_port_does_not_hide_disappearing_host(self):
        a, b = self.host('192.0.2.1'), self.host('192.0.2.2')
        for target in ('192.0.2.0/24', 'example.test'):
            with self.subTest(target=target):
                diff = compare_sessions(self.session(1, a+b, target), self.session(2, b, target))
                self.assertTrue(diff['port_comparison_reliable'])
                self.assertEqual(set(diff['missing_ports']), {'192.0.2.1 80/tcp'})
                self.assertEqual(diff['service_changes'], [])

    def test_change_is_attributed_to_correct_host(self):
        a, b = self.host('192.0.2.1'), self.host('192.0.2.2')
        diff = compare_sessions(self.session(1, a+b),
                                self.session(2, a+self.host('192.0.2.2', 'Apache')))
        self.assertEqual([c['port'] for c in diff['service_changes']], ['192.0.2.2 80/tcp'])
        from penx_app.application.scan_trends import report_text
        self.assertIn('192.0.2.2 80/tcp', report_text(diff))

    def test_ambiguous_host_identity_is_inconclusive(self):
        a = self.host('192.0.2.1')
        for hosts in (a+self.host(''), a+a):
            with self.subTest(hosts=hosts):
                diff = compare_sessions(self.session(1, a), self.session(2, hosts))
                self.assertFalse(diff['port_comparison_reliable'])
                self.assertEqual(diff['missing_ports'], {})
                self.assertEqual(diff['service_changes'], [])

    def test_unattributed_subnet_text_is_inconclusive(self):
        old, new = self.session(1, ''), self.session(2, '')
        old['summary'] = (1, 1, '80/tcp open http\nNmap done:', '', 'LOW')
        new['summary'] = (2, 2, '443/tcp open https\nNmap done:', '', 'LOW')
        diff = compare_sessions(old, new)
        self.assertFalse(diff['port_comparison_reliable'])
        self.assertEqual(diff['missing_ports'], {})


if __name__ == '__main__':
    unittest.main(verbosity=2)
