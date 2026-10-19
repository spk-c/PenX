"""Second audit regressions for evidence integrity and secret-safe exports.

All inputs are synthetic; no network scans or external hosts are contacted.
"""
from __future__ import annotations

import json
from unittest import TestCase
from unittest.mock import Mock, patch

import requests

from penx_app.reporting.machine_reports import report_payload, sarif_payload
from penx_app.scanners.scan_results import recon_has_evidence
from penx_app.scanners.tools import run_curl_headers, run_whatweb


class PassiveEvidenceRegressionTests(TestCase):
    def test_empty_whois_and_empty_rdap_do_not_start_assessment(self):
        raw = (
            "[PASSIVE-ONLY RECON: example.test]\n"
            "Only external data sources queried.\n\n"
            "[WHOIS REGISTRY]\n"
            "[Python WHOIS]\nNo registration details returned.\n\n"
            "[DNS VIA RESOLVER]\n"
            "A: unavailable (Timeout)\nAAAA: unavailable (Timeout)\n\n"
            "[CERTIFICATE TRANSPARENCY]\nNo entries returned.\n\n"
            "[RDAP]\n{}\n\n"
            "[SHODAN LOOKUP] No public IPv4 addresses; skipped."
        )
        self.assertFalse(recon_has_evidence(raw, passive_only=True))

    def test_whois_registration_fields_are_evidence(self):
        raw = "[WHOIS REGISTRY]\n[Python WHOIS]\nregistrar: Example Registry"
        self.assertTrue(recon_has_evidence(raw, passive_only=True))

    def test_rdap_nonempty_metadata_is_evidence(self):
        raw = '[RDAP]\n{"name":"example.test"}'
        self.assertTrue(recon_has_evidence(raw, passive_only=True))
        self.assertFalse(recon_has_evidence("[RDAP]\nnull", passive_only=True))
        self.assertFalse(recon_has_evidence("[RDAP]\n[]", passive_only=True))


def report_fixture(target: str):
    quote = "443/tcp open https"
    return {
        "history": (2, target, "2026-10-19", "active"),
        "summary": (1, 2, "[ NMAP OUTPUT ]\n" + quote, "AI description", "LOW"),
        "vulns": [(
            1, 2, "Target: example.test", "medium", "confirmed",
            "example.test:443", "https://example.test/admin",
            "Evidence: " + quote + "\nHost example.test is in scope."
        )],
        "fixes": [], "corrections": [],
    }


class MachineReportUrlRedactionTests(TestCase):
    def test_url_target_hostname_is_redacted_in_json_and_sarif(self):
        fixture = report_fixture("https://Example.Test:8443/admin")
        for exporter in (report_payload, sarif_payload):
            with self.subTest(exporter=exporter.__name__):
                data = json.dumps(exporter(fixture, redact=True))
                self.assertNotIn("example.test", data.lower())
                self.assertNotIn("Example.Test", data)
                self.assertIn("[TARGET REDACTED]", data)
                self.assertIn("443", data)

    def test_subdomain_is_not_accidentally_masked_as_same_target(self):
        fixture = report_fixture("https://example.test:443/")
        value = "api.example.test and example.test"
        from penx_app.reporting.machine_reports import _mask
        self.assertEqual(
            _mask(value, fixture["history"][1], True),
            "api.example.test and [TARGET REDACTED]",
        )

    def test_malformed_legacy_url_does_not_crash_redaction(self):
        from penx_app.reporting.machine_reports import _mask
        self.assertEqual(_mask("text", "https://[invalid", True), "text")


class HttpEvidencePrivacyTests(TestCase):
    def test_headers_do_not_expose_secrets_or_forged_lines(self):
        origin = "https://example.test/login?token=ORIGINAL_SECRET"
        response = Mock(status_code=302, url=origin)
        response.headers = {
            "Location": "https://example.test/callback?code=REDIRECT_SECRET",
            "X-API-Key": "API_SECRET",
            "X-CSRF-Token": "CSRF_SECRET",
            "Set-Cookie": "id=COOKIE_SECRET; HttpOnly; Secure",
            "Link": "<https://example.test/call?access=LINK_SECRET>; rel=next",
            "Server": "nginx",
            "X-Test": "safe\n[FAKE EVIDENCE] status 200",
        }
        with patch("penx_app.scanners.tools._urls", return_value=[origin]), \
             patch("penx_app.scanners.tools.requests.head", return_value=response):
            report = run_curl_headers("example.test")
        self.assertEqual(report.status, "COMPLETE")
        for secret in (
            "ORIGINAL_SECRET", "REDIRECT_SECRET", "API_SECRET",
            "CSRF_SECRET", "COOKIE_SECRET", "LINK_SECRET",
        ):
            with self.subTest(secret=secret):
                self.assertNotIn(secret, report)
        self.assertIn("Location: [URL PARAMETERS REDACTED]", report)
        self.assertIn("X-API-Key: [REDACTED]", report)
        self.assertIn("Server: nginx", report)
        self.assertIn("Set-Cookie: [REDACTED]", report)
        self.assertNotIn("\n[FAKE EVIDENCE]", report)
        self.assertIn("X-Test: safe [FAKE EVIDENCE]", report)

    def test_exception_messages_do_not_include_embedded_query_values(self):
        origin = "https://example.test/private?token=ORIGINAL_SECRET"
        with patch("penx_app.scanners.tools._urls", return_value=[origin]), \
             patch("penx_app.scanners.tools.requests.head",
                   side_effect=requests.ConnectionError("Request url token=LEAKED_SECRET")):
            report = run_curl_headers("example.test")
        self.assertEqual(report.status, "FAILED")
        self.assertIn("ConnectionError", report)
        self.assertNotIn("LEAKED_SECRET", report)
        self.assertNotIn("ORIGINAL_SECRET", report)

    def test_whatweb_python_fallback_redacts_query(self):
        origin = "https://example.test/?token=ORIGINAL_SECRET"
        response = Mock(status_code=200, url=origin)
        response.encoding = "utf-8"
        response.headers = {"Server": "nginx"}
        response.raw.read.return_value = b"<html><head></head></html>"
        with patch("penx_app.scanners.tools.WHATWEB_PATH", ""), \
             patch("penx_app.scanners.tools._executable", return_value=None), \
             patch("penx_app.scanners.tools._urls", return_value=[origin]), \
             patch("penx_app.scanners.tools.requests.get", return_value=response):
            report = run_whatweb("example.test")
        self.assertEqual(report.status, "PARTIAL")
        self.assertTrue(report.evidence)
        self.assertNotIn("ORIGINAL_SECRET", report)
        self.assertIn("Server=nginx", report)


if __name__ == "__main__":
    import unittest
    unittest.main()
