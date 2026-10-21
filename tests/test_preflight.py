"""P1-4: offline preflight / dry-run availability (mocked resolvers only)."""
import contextlib
import importlib.util
import os
import unittest
from unittest import mock

from penx_app.application import preflight
from penx_app.application.preflight import (
    build_preflight,
    format_report,
    main,
    scanner_availability,
)
from penx_app.application.scan_profiles import (
    BUILTIN_PROFILES,
    build_custom_plan,
    profile_to_plan,
)
from penx_app.domain.scan_plan import PlanValidationError, ScanPlan
from penx_app.domain.scan_models import ScannerOutput
from penx_app.scanners.registry import SCANNERS


@contextlib.contextmanager
def mocked_resolvers(*, nmap=True, npcap=True, ruby=True, perl=True,
                    whatweb_script=True, nikto_script=True,
                    whois=True, dns=True, requests=True,
                    binaries=(), version='v1.2.3', version_ok=True,
                    os_name=None):
    """Patch every preflight resolver; `binaries` = names found on PATH."""
    lib_present = {'whois': whois, 'dns': dns, 'requests': requests}
    runtime_present = {'ruby': ruby, 'perl': perl}

    def which(name, *args, **kwargs):
        return '/bin/' + name if name in binaries else None

    def find_runtime(tool):
        if tool in runtime_present:
            return '/bin/' + tool if runtime_present[tool] else None
        return '/bin/' + tool

    def find_spec(name, *args, **kwargs):
        if name in lib_present:
            return mock.Mock() if lib_present[name] else None
        return mock.Mock()

    def run_tool(command, timeout=120, **kwargs):
        if not version_ok:
            return ScannerOutput(
                '[!] Timed out after 10s: ' + command[0],
                status='PARTIAL', evidence=False)
        return ScannerOutput(version + '\nsecond line',
                             status='COMPLETE', evidence=True)

    fake_whatweb = mock.Mock()
    fake_whatweb.is_file.return_value = whatweb_script
    fake_nikto = mock.Mock()
    fake_nikto.is_file.return_value = nikto_script

    with contextlib.ExitStack() as stack:
        stack.enter_context(mock.patch('shutil.which', side_effect=which))
        stack.enter_context(mock.patch.object(
            preflight, 'find_nmap',
            return_value='/usr/bin/nmap' if nmap else None))
        stack.enter_context(mock.patch.object(
            preflight, 'npcap_present', return_value=npcap))
        stack.enter_context(mock.patch.object(
            preflight, 'find_runtime', side_effect=find_runtime))
        stack.enter_context(mock.patch.object(
            importlib.util, 'find_spec', side_effect=find_spec))
        stack.enter_context(mock.patch.object(
            preflight, 'run_tool', side_effect=run_tool))
        stack.enter_context(mock.patch.object(
            preflight, 'WHATWEB_SCRIPT', fake_whatweb))
        stack.enter_context(mock.patch.object(
            preflight, 'NIKTO_SCRIPT', fake_nikto))
        stack.enter_context(mock.patch.dict(os.environ, {
            'PENX_NUCLEI_PATH': '', 'PENX_HTTPX_PATH': '',
            'PENX_FFUF_PATH': '', 'PENX_SUBFINDER_PATH': '',
            'PENX_KATANA_PATH': '',
        }))
        if os_name is not None:
            stack.enter_context(mock.patch.object(preflight.os, 'name', os_name))
        yield


class AvailabilityMatrixTests(unittest.TestCase):
    """One case per registry key: exact missing tuple and available flag."""

    def test_nmap_available(self):
        with mocked_resolvers(nmap=True):
            item = scanner_availability('1')
        self.assertTrue(item.available)
        self.assertEqual(item.missing, ())
        self.assertEqual(item.version, 'v1.2.3')

    def test_nmap_missing(self):
        with mocked_resolvers(nmap=False):
            item = scanner_availability('1')
        self.assertFalse(item.available)
        self.assertEqual(item.missing, ('nmap',))
        self.assertIsNone(item.version)

    def test_nmap_without_npcap_still_available_with_note(self):
        with mocked_resolvers(nmap=True, npcap=False, os_name='nt'):
            item = scanner_availability('1')
        self.assertTrue(item.available)
        self.assertIn('Npcap', item.note)

    def test_whois_available(self):
        with mocked_resolvers(whois=True):
            item = scanner_availability('2')
        self.assertTrue(item.available)
        self.assertEqual(item.missing, ())

    def test_whois_missing(self):
        with mocked_resolvers(whois=False):
            item = scanner_availability('2')
        self.assertFalse(item.available)
        self.assertEqual(item.missing, ('python-whois',))

    def test_whatweb_available(self):
        with mocked_resolvers(ruby=True, whatweb_script=True):
            item = scanner_availability('3')
        self.assertTrue(item.available)
        self.assertEqual(item.missing, ())
        self.assertEqual(item.version, 'v1.2.3')

    def test_whatweb_missing_ruby_only(self):
        with mocked_resolvers(ruby=False, whatweb_script=True):
            item = scanner_availability('3')
        self.assertFalse(item.available)
        self.assertEqual(item.missing, ('ruby',))

    def test_whatweb_missing_script_only(self):
        with mocked_resolvers(ruby=True, whatweb_script=False):
            item = scanner_availability('3')
        self.assertFalse(item.available)
        self.assertEqual(item.missing, ('vendor/whatweb/whatweb',))

    def test_whatweb_missing_both(self):
        with mocked_resolvers(ruby=False, whatweb_script=False):
            item = scanner_availability('3')
        self.assertFalse(item.available)
        self.assertEqual(item.missing, ('ruby', 'vendor/whatweb/whatweb'))

    def test_http_headers_always_available(self):
        with mocked_resolvers(nmap=False, whois=False, binaries=()):
            item = scanner_availability('4')
        self.assertTrue(item.available)
        self.assertEqual(item.missing, ())
        self.assertIn('builtin', item.version)

    def test_dns_available(self):
        with mocked_resolvers(dns=True):
            item = scanner_availability('5')
        self.assertTrue(item.available)
        self.assertEqual(item.missing, ())

    def test_dns_missing(self):
        with mocked_resolvers(dns=False):
            item = scanner_availability('5')
        self.assertFalse(item.available)
        self.assertEqual(item.missing, ('dnspython',))

    def test_nikto_available(self):
        with mocked_resolvers(perl=True, nikto_script=True):
            item = scanner_availability('6')
        self.assertTrue(item.available)
        self.assertEqual(item.missing, ())

    def test_nikto_missing_perl_only(self):
        with mocked_resolvers(perl=False, nikto_script=True):
            item = scanner_availability('6')
        self.assertFalse(item.available)
        self.assertEqual(item.missing, ('perl',))

    def test_nikto_missing_script_only(self):
        with mocked_resolvers(perl=True, nikto_script=False):
            item = scanner_availability('6')
        self.assertFalse(item.available)
        self.assertEqual(item.missing, ('vendor/nikto/program/nikto.pl',))

    def test_nuclei_available(self):
        with mocked_resolvers(binaries=('nuclei',)):
            item = scanner_availability('7')
        self.assertTrue(item.available)
        self.assertEqual(item.missing, ())

    def test_nuclei_missing(self):
        with mocked_resolvers(binaries=()):
            item = scanner_availability('7')
        self.assertFalse(item.available)
        self.assertEqual(item.missing, ('nuclei',))

    def test_httpx_available(self):
        with mocked_resolvers(binaries=('httpx',)):
            item = scanner_availability('8')
        self.assertTrue(item.available)
        self.assertEqual(item.missing, ())

    def test_httpx_missing(self):
        with mocked_resolvers(binaries=()):
            item = scanner_availability('8')
        self.assertFalse(item.available)
        self.assertEqual(item.missing, ('httpx',))

    def test_ffuf_available(self):
        with mocked_resolvers(binaries=('ffuf',)):
            item = scanner_availability('9')
        self.assertTrue(item.available)
        self.assertEqual(item.missing, ())

    def test_ffuf_missing(self):
        with mocked_resolvers(binaries=()):
            item = scanner_availability('9')
        self.assertFalse(item.available)
        self.assertEqual(item.missing, ('ffuf',))

    def test_endpoint_mapping_available(self):
        with mocked_resolvers(requests=True):
            item = scanner_availability('e')
        self.assertTrue(item.available)
        self.assertEqual(item.missing, ())

    def test_endpoint_mapping_missing(self):
        with mocked_resolvers(requests=False):
            item = scanner_availability('e')
        self.assertFalse(item.available)
        self.assertEqual(item.missing, ('requests',))

    def test_subfinder_available(self):
        with mocked_resolvers(binaries=('subfinder',)):
            item = scanner_availability('s')
        self.assertTrue(item.available)
        self.assertEqual(item.missing, ())

    def test_subfinder_missing(self):
        with mocked_resolvers(binaries=()):
            item = scanner_availability('s')
        self.assertFalse(item.available)
        self.assertEqual(item.missing, ('subfinder',))

    def test_katana_available(self):
        with mocked_resolvers(binaries=('katana',)):
            item = scanner_availability('c')
        self.assertTrue(item.available)
        self.assertEqual(item.missing, ())

    def test_katana_missing(self):
        with mocked_resolvers(binaries=()):
            item = scanner_availability('c')
        self.assertFalse(item.available)
        self.assertEqual(item.missing, ('katana',))

    def test_tls_always_available(self):
        with mocked_resolvers(nmap=False, whois=False, binaries=()):
            item = scanner_availability('d')
        self.assertTrue(item.available)
        self.assertEqual(item.missing, ())
        self.assertIn('builtin', item.version)

    def test_unknown_key_raises(self):
        with self.assertRaises(KeyError):
            scanner_availability('z')


class VersionProbeTests(unittest.TestCase):
    def test_first_nonempty_line_is_the_version(self):
        with mocked_resolvers(
                nmap=True,
                version='Nmap version 7.93 ( https://nmap.org )\nCopyright'):
            item = scanner_availability('1')
        self.assertEqual(item.version, 'Nmap version 7.93 ( https://nmap.org )')

    def test_failing_probe_keeps_availability(self):
        with mocked_resolvers(nmap=True, version_ok=False):
            item = scanner_availability('1')
        self.assertTrue(item.available)
        self.assertIsNone(item.version)

    def test_raising_probe_keeps_availability(self):
        with mocked_resolvers(nmap=True):
            with mock.patch.object(preflight, 'run_tool',
                                   side_effect=RuntimeError('boom')):
                item = scanner_availability('1')
        self.assertTrue(item.available)
        self.assertIsNone(item.version)

    def test_probe_failure_tolerant_for_go_tools(self):
        with mocked_resolvers(binaries=('nuclei',), version_ok=False):
            item = scanner_availability('7')
        self.assertTrue(item.available)
        self.assertIsNone(item.version)


class DryRunContractTests(unittest.TestCase):
    def test_build_preflight_dispatches_no_adapters_and_no_network(self):
        calls = []
        menu = {key: (key, (lambda key=key: calls.append(key) or 'output'))
                for key in SCANNERS}
        with mocked_resolvers():
            with mock.patch('socket.socket',
                            side_effect=AssertionError('socket used')), \
                 mock.patch('requests.head',
                            side_effect=AssertionError('requests used')), \
                 mock.patch('requests.get',
                            side_effect=AssertionError('requests used')):
                plan = build_custom_plan(
                    'example.test', ('1', '2', '3', '4', '5'),
                    active_consent=False)
                report = build_preflight(plan)
        self.assertEqual(calls, [])
        self.assertEqual(len(report.availability), 5)
        self.assertTrue(report.available)

    def test_availability_follows_schedule_order(self):
        with mocked_resolvers():
            plan = build_custom_plan(
                'example.test', ('d', '1', '9'), active_consent=True)
            report = build_preflight(plan)
        self.assertEqual(report.schedule, ('1', '9', 'd'))
        self.assertEqual([item.key for item in report.availability],
                         list(report.schedule))

    def test_same_environment_same_report(self):
        plan = build_custom_plan('example.test', ('1', '4'),
                                 active_consent=False)
        with mocked_resolvers():
            first = build_preflight(plan)
        with mocked_resolvers():
            second = build_preflight(plan)
        self.assertEqual(first, second)
        self.assertEqual(format_report(first), format_report(second))

    def test_invalid_plan_raises(self):
        bad = ScanPlan('p', 1, 'example.test', (), False, False, {}, 1,
                       None, None)
        with self.assertRaises(PlanValidationError):
            build_preflight(bad)

    def test_passive_plan_is_available_with_empty_schedule(self):
        plan = profile_to_plan(BUILTIN_PROFILES['passive'], 'example.test',
                               active_consent=False)
        report = build_preflight(plan)
        self.assertTrue(report.available)
        self.assertEqual(report.availability, ())

    def test_consent_reminder_for_consent_keys(self):
        with mocked_resolvers(binaries=('nuclei',)):
            plan = build_custom_plan('example.test', ('7',),
                                     active_consent=True)
            report = build_preflight(plan)
        self.assertIn('Consent reminder', format_report(report))

    def test_report_names_target_profile_and_schedule(self):
        with mocked_resolvers():
            plan = build_custom_plan('example.test', ('4', 'd'),
                                     active_consent=False)
            report = build_preflight(plan)
        text = format_report(report)
        self.assertIn('example.test', text)
        self.assertIn('custom v1', text)
        self.assertIn('4, d', text)


class MainExitCodeTests(unittest.TestCase):
    def test_usage_error_without_target(self):
        self.assertEqual(main([]), 2)

    def test_usage_error_with_blank_target(self):
        self.assertEqual(main(['--target', '   ']), 2)

    def test_missing_scanner_exits_1(self):
        with mocked_resolvers(nmap=False):
            self.assertEqual(
                main(['--target', 'example.test', '--scanners', '1']), 1)

    def test_all_available_exits_0(self):
        with mocked_resolvers(nmap=True):
            self.assertEqual(
                main(['--target', 'example.test', '--scanners', '1,4,d']), 0)

    def test_passive_profile_exits_0(self):
        self.assertEqual(
            main(['--target', 'example.test', '--profile', 'passive']), 0)

    def test_consent_missing_exits_1(self):
        with mocked_resolvers():
            self.assertEqual(
                main(['--target', 'example.test', '--scanners', '7']), 1)

    def test_consent_given_exits_0(self):
        with mocked_resolvers(binaries=('nuclei',)):
            self.assertEqual(
                main(['--target', 'example.test', '--scanners', '7',
                      '--consent']), 0)

    def test_unknown_scanner_key_exits_1(self):
        self.assertEqual(
            main(['--target', 'example.test', '--scanners', 'z']), 1)

    def test_unknown_profile_exits_1(self):
        self.assertEqual(
            main(['--target', 'example.test', '--profile', 'nope']), 1)


if __name__ == '__main__':
    unittest.main()
