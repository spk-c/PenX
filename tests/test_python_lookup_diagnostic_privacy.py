"""PX-003: offline Python WHOIS/DNS failures must not disclose provider diagnostics.

These tests use only synthetic exceptions and mocked resolvers, never target I/O.
"""
from __future__ import annotations

from contextlib import ExitStack
import json
import sys
import types
import unittest
from unittest.mock import patch

import dns.exception
import dns.resolver

from penx_app.application.headless_scan import scan_report
from penx_app.application.scan_profiles import build_custom_plan
from penx_app.application.scanner_execution import run_selected_structured
from penx_app.domain.scan_models import ScanRequest
from penx_app.reporting.machine_reports import sarif_from_report
from penx_app.scanners import tools

SECRET = "CANARY-FAKE-SECRET-NOT-A-CREDENTIAL"
UNTRUSTED_ERROR = (
    "synthetic provider exception at "
    "https://example.test/private?api_key=" + SECRET
)


class PythonLookupDiagnosticPrivacyTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.io_guards = [
            self.stack.enter_context(patch(name, side_effect=AssertionError("offline fixture I/O")))
            for name in ("socket.socket.connect", "socket.getaddrinfo",
                         "requests.Session.request", "subprocess.Popen")
        ]

    def tearDown(self):
        for guard in self.io_guards:
            guard.assert_not_called()

    def assert_export_preserves_status_and_privacy(self, key, output):
        self.assertNotIn(SECRET, str(output) + output.diagnostics)
        result = run_selected_structured(
            ScanRequest("example.test", (key,)),
            menu={key: ("synthetic", lambda _target: output)},
        )
        plan = build_custom_plan("example.test", (key,), active_consent=False)
        report = scan_report(plan, result)
        sarif = sarif_from_report(report)
        self.assertEqual(report["adapters"][0]["status"], output.status)
        self.assertEqual(report["adapters"][0]["evidence"], output.evidence)
        self.assertNotIn(SECRET, json.dumps(report) + json.dumps(sarif))
        self.assertEqual(len(report["findings"]), 0)
        self.assertEqual(len(sarif["runs"][0]["results"]), 0)

    def test_whois_exception_detail_is_omitted(self):
        def failed_whois(_host):
            raise RuntimeError(UNTRUSTED_ERROR)
        with patch.dict(sys.modules, {"whois": types.SimpleNamespace(whois=failed_whois)}):
            outcome = tools.run_whois("example.test")
        self.assertEqual(outcome.status, "FAILED")
        self.assertFalse(outcome.evidence)
        self.assertIn("RuntimeError", str(outcome))
        self.assert_export_preserves_status_and_privacy("2", outcome)

    def test_dns_all_provider_errors_never_leak(self):
        with patch.object(dns.resolver, "resolve",
                          side_effect=dns.exception.DNSException(UNTRUSTED_ERROR)) as resolve:
            outcome = tools.run_dig("example.test")
        self.assertEqual(resolve.call_count, 5)
        self.assertEqual(outcome.status, "FAILED")
        self.assertFalse(outcome.evidence)
        self.assertIn("DNSException", str(outcome))
        self.assert_export_preserves_status_and_privacy("5", outcome)

    def test_dns_good_record_and_provider_errors_are_partial(self):
        def lookup(_host, rrtype, *, lifetime):
            self.assertEqual(lifetime, 8)
            if rrtype == "A":
                return ["192.0.2.20"]
            raise dns.exception.DNSException(UNTRUSTED_ERROR)
        with patch.object(dns.resolver, "resolve", side_effect=lookup) as resolve:
            outcome = tools.run_dig("example.test")
        self.assertEqual(resolve.call_count, 5)
        self.assertEqual(outcome.status, "PARTIAL")
        self.assertTrue(outcome.evidence)
        self.assertIn("192.0.2.20", str(outcome))
        self.assertIn("DNSException", str(outcome))
        self.assert_export_preserves_status_and_privacy("5", outcome)

    def test_dns_no_answer_is_not_an_error_or_evidence(self):
        with patch.object(dns.resolver, "resolve", side_effect=dns.resolver.NoAnswer):
            outcome = tools.run_dig("example.test")
        self.assertEqual(outcome.status, "FAILED")
        self.assertFalse(outcome.evidence)
        self.assertIn("(no record)", str(outcome))
        self.assert_export_preserves_status_and_privacy("5", outcome)


if __name__ == "__main__":
    unittest.main()
