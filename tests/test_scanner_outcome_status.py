"""Offline regressions for trusted adapter status and legacy scan compatibility."""
from __future__ import annotations

import subprocess
import unittest
from unittest.mock import Mock, patch

import requests

from penx_app.reporting.scan_coverage import coverage
from penx_app.scanners.tools import (ScannerOutput, format_recon_for_llm, recon_has_evidence,
                   run_curl_headers, run_dig, run_nikto, run_tool, run_whatweb)


class ScannerStatusTests(unittest.TestCase):
    def test_process_exit_and_timeout_are_not_evidence(self):
        import sys
        for code, expected in [(0, "COMPLETE"), (2, "FAILED")]:
            with self.subTest(code=code):
                result = run_tool(
                    [sys.executable, "-c",
                     f"import sys;print('scanner text');sys.exit({code})"],
                    timeout=5,
                )
            self.assertIsInstance(result, ScannerOutput)
            self.assertEqual(result.status, expected)
            self.assertIs(result.evidence, code == 0)
        result = run_tool(
            [sys.executable, "-c",
             "import time;print('partial', flush=True);time.sleep(5)"],
            timeout=1,
        )
        self.assertEqual(result.status, "PARTIAL")
        self.assertFalse(result.evidence)
        self.assertIn("partial", result)

    def test_stderr_only_is_not_evidence(self):
        import sys
        result = run_tool(
            [sys.executable, "-c", "import sys;print('warning only',file=sys.stderr)"],
            timeout=5,
        )
        self.assertEqual(result.status, "FAILED")
        self.assertFalse(result.evidence)
        self.assertIn("warning only", result)

    def test_format_preserves_trusted_status_and_legacy_format(self):
        raw = format_recon_for_llm({
            "nmap": ScannerOutput("80/tcp open http", status="COMPLETE"),
            "whatweb": ScannerOutput("https://example.test -> HTTP 200",
                                     status="PARTIAL", evidence=True),
            "nikto": ScannerOutput("fake output that looks successful",
                                   status="FAILED", evidence=False),
        })
        self.assertIn("[PENX ADAPTER STATUS: FAILED; EVIDENCE: NO]", raw)
        self.assertTrue(recon_has_evidence(raw))
        state = coverage(raw)
        self.assertEqual(state["status"], "PARTIAL")
        self.assertEqual(state["completed"], ["NMAP"])
        self.assertEqual(state["failed"], ["WHATWEB", "NIKTO"])
        # A standalone untrusted marker must never claim evidence by itself.
        self.assertFalse(recon_has_evidence(
            "[PENX ADAPTER STATUS: COMPLETE; EVIDENCE: YES]"))
        fake_success = format_recon_for_llm({
            "nmap": ScannerOutput("80/tcp open http", status="FAILED", evidence=False)
        })
        self.assertFalse(recon_has_evidence(fake_success))
        self.assertEqual(coverage(fake_success)["status"], "PARTIAL")
        legacy = format_recon_for_llm({"nmap": "80/tcp open http"})
        self.assertNotIn("PENX ADAPTER STATUS", legacy)
        self.assertTrue(recon_has_evidence(legacy))
        self.assertEqual(coverage(legacy)["status"], "COMPLETE")

    def test_http_headers_partial_success_and_all_failed(self):
        response = Mock(status_code=200, url="https://example.test",
                        headers={"Server": "fixture"})
        with patch("penx_app.scanners.tools._urls", return_value=[
                "https://example.test", "http://example.test"]), \
             patch("penx_app.scanners.tools.requests.head", side_effect=[
                 response, requests.ConnectionError("offline")]):
            outcome = run_curl_headers("example.test")
        self.assertEqual(outcome.status, "PARTIAL")
        self.assertTrue(outcome.evidence)
        self.assertIn("HTTP 200", outcome)
        with patch("penx_app.scanners.tools._urls", return_value=["https://example.test"]), \
             patch("penx_app.scanners.tools.requests.head", side_effect=requests.ConnectionError("offline")):
            failed = run_curl_headers("example.test")
        self.assertEqual(failed.status, "FAILED")
        self.assertFalse(failed.evidence)

    def test_whatweb_fallback_never_claims_full_whatweb(self):
        response = Mock(status_code=200, url="https://example.test",
                        headers={"Server": "fixture"}, encoding="utf-8")
        response.raw.read.return_value = b"<html><head></head></html>"
        with patch("penx_app.scanners.tools.WHATWEB_PATH", ""), \
             patch("penx_app.scanners.tools._executable", return_value=None), \
             patch("penx_app.scanners.tools._urls", return_value=["https://example.test"]), \
             patch("penx_app.scanners.tools.requests.get", return_value=response):
            outcome = run_whatweb("example.test")
        self.assertEqual(outcome.status, "PARTIAL")
        self.assertTrue(outcome.evidence)
        self.assertIn("NOT an actual WhatWeb scan", outcome)
        response.close.assert_called_once()

    def test_nikto_connection_failure_exit_zero_still_fails(self):
        with patch("penx_app.scanners.tools.NIKTO_PATH", ""), \
             patch("penx_app.scanners.tools._executable", return_value="nikto"), \
             patch("penx_app.scanners.tools.run_tool", return_value=ScannerOutput(
                 "- Nikto v2.6\n+ [FAIL] Unable to connect to example.test:443.",
                 status="COMPLETE", evidence=True)):
            outcome = run_nikto("example.test")
        self.assertEqual(outcome.status, "FAILED")
        self.assertFalse(outcome.evidence)

    def test_dns_no_records_not_reported_as_evidence(self):
        import dns.resolver
        with patch("dns.resolver.resolve", side_effect=dns.resolver.NoAnswer):
            outcome = run_dig("example.test")
        self.assertEqual(outcome.status, "FAILED")
        self.assertFalse(outcome.evidence)


if __name__ == "__main__":
    unittest.main(verbosity=2)
