"""Live PHP2Shell header assessment: isolated, non-exploiting regression tests."""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import unittest
from unittest.mock import patch

from penx_app.intelligence.php2shell_audit import (
    assess_php2shell, classify_live_php2shell_headers,
)
from penx_app.reporting.machine_reports import report_payload, sarif_payload
from penx_app.scanners.tools import run_curl_headers
from penx_app.scanners.scan_results import format_recon_for_llm


class FakeResponse:
    def __init__(self, version: str | None = None, *, status_code: int = 200):
        self.url = "https://fixture.invalid/"
        self.status_code = status_code
        self.headers = ({"Server": "nginx", "X-Powered-By": version}
                        if version is not None else {"Server": "nginx"})
        self.closed = False

    def close(self):
        self.closed = True


class LivePhp2ShellTests(unittest.TestCase):
    def test_release_version_matrix(self):
        for version, expected in (
            ("PHP/8.2.34", "POTENTIALLY_VULNERABLE"),
            ("PHP/8.3.35", "POTENTIALLY_VULNERABLE"),
            ("PHP/8.4.26", "POTENTIALLY_VULNERABLE"),
            ("PHP/8.5.11", "POTENTIALLY_VULNERABLE"),
            ("PHP/8.1.30", "POTENTIALLY_VULNERABLE"),
            ("PHP/8.2.35", "UNVERIFIED"),
            ("PHP/8.3.36", "UNVERIFIED"),
            ("PHP/8.4.27", "UNVERIFIED"),
            ("PHP/8.5.12", "UNVERIFIED"),
        ):
            with self.subTest(version=version):
                result = classify_live_php2shell_headers([version])
                self.assertEqual(result["status"], expected)
                self.assertFalse(result["patch_verified"])
                self.assertFalse(result["rce_confirmed"])
                self.assertFalse(result["exploit_tested"])

    def test_hidden_conflicting_or_unrecognized_php_never_claims_safe(self):
        for values in ([], ["Apache/2.4"], ["PHP/8.4.26", "PHP/8.4.27"],
                       ["PHP/8.4.27", "PHP/8.4.27"],
                       ["PHP/8.4.26; wrong"], ["PHP/8.4.26\nX:evil"]):
            expected = ("POTENTIALLY_VULNERABLE"
                        if values == ["PHP/8.4.26", "PHP/8.4.26"]
                        else "UNVERIFIED")
            with self.subTest(values=values):
                self.assertEqual(classify_live_php2shell_headers(values)["status"], expected)

    def test_uses_only_existing_head_request_for_positive_indicator(self):
        response = FakeResponse("PHP/8.4.26")
        with patch("penx_app.scanners.tools.requests.head", return_value=response) as head, \
             patch("penx_app.scanners.tools.requests.get") as get, \
             patch("penx_app.scanners.tools._urls", return_value=["https://fixture.invalid/"]):
            output = run_curl_headers("fixture.invalid")
        self.assertTrue(response.closed)
        self.assertEqual(output.status, "COMPLETE")
        self.assertIn("[PENX PHP2SHELL LIVE] POTENTIALLY_VULNERABLE", str(output))
        self.assertEqual(head.call_count, 1)
        self.assertEqual(get.call_count, 0)
        self.assertFalse(head.call_args.kwargs["allow_redirects"])

    def test_live_result_is_exported_but_never_as_confirmed_vulnerability(self):
        response = FakeResponse("PHP/8.4.26")
        with patch("penx_app.scanners.tools.requests.head", return_value=response), \
             patch("penx_app.scanners.tools.requests.get") as get, \
             patch("penx_app.scanners.tools._urls", return_value=["https://fixture.invalid/"]):
            output = run_curl_headers("fixture.invalid")
        raw = format_recon_for_llm({"HTTP headers": output})
        advisory = assess_php2shell(raw)
        self.assertEqual(advisory["verification_status"], "POTENTIALLY_VULNERABLE")
        self.assertTrue(advisory["live_header_check_observed"])
        self.assertFalse(advisory["rce_confirmed"])
        self.assertFalse(advisory["patch_verified"])
        data = {
            "history": (1, "fixture.invalid", "2026-10-21", "active"),
            "summary": (1, 1, raw, "Live scan observation", "UNKNOWN",
                        "test-model", "2026-10-21"),
            "vulns": [], "corrections": [],
        }
        exported = report_payload(data)
        self.assertEqual(exported["php2shell"]["verification_status"], "POTENTIALLY_VULNERABLE")
        self.assertTrue(exported["php2shell"]["live_header_check_observed"])
        self.assertEqual(exported["findings"], [])
        sarif = sarif_payload(data)
        self.assertEqual(sarif["runs"][0]["results"], [])
        self.assertEqual(sarif["runs"][0]["properties"]["php2shell"]["verification_status"],
                         "POTENTIALLY_VULNERABLE")
        get.assert_not_called()

    def test_real_loopback_http_head_no_exploit_or_extra_requests(self):
        """True socket round-trip against a local fixture, never a public host."""
        class LocalHandler(BaseHTTPRequestHandler):
            calls: list[str] = []
            def do_HEAD(self):
                LocalHandler.calls.append("HEAD")
                self.send_response(200)
                self.send_header("X-Powered-By", "PHP/8.4.26")
                self.send_header("Content-Length", "0")
                self.end_headers()
            def do_GET(self):
                LocalHandler.calls.append("GET")
                self.send_response(405)
                self.end_headers()
            def do_POST(self):
                LocalHandler.calls.append("POST")
                self.send_response(405)
                self.end_headers()
            def log_message(self, *_args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), LocalHandler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            url = "http://127.0.0.1:" + str(server.server_port) + "/"
            live_output = run_curl_headers(url)
            self.assertEqual(live_output.status, "COMPLETE")
            self.assertIn("[PENX PHP2SHELL LIVE] POTENTIALLY_VULNERABLE",
                          str(live_output))
            self.assertEqual(LocalHandler.calls, ["HEAD"])
            report = assess_php2shell(format_recon_for_llm(
                {"HTTP headers": live_output}
            ))
            self.assertTrue(report["live_header_check_observed"])
            self.assertFalse(report["rce_confirmed"])
            self.assertFalse(report["patch_verified"])
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=3)

    def test_patched_looking_header_is_not_patch_verified(self):
        response = FakeResponse("PHP/8.4.27")
        with patch("penx_app.scanners.tools.requests.head", return_value=response), \
             patch("penx_app.scanners.tools.requests.get") as get, \
             patch("penx_app.scanners.tools._urls", return_value=["https://fixture.invalid/"]):
            output = run_curl_headers("fixture.invalid")
        self.assertIn("[PENX PHP2SHELL LIVE] UNVERIFIED", str(output))
        self.assertEqual(assess_php2shell(format_recon_for_llm({"HTTP headers": output}))
                         ["verification_status"], "UNVERIFIED")
        get.assert_not_called()

    def test_failed_requests_do_not_fabricate_checked_status(self):
        import requests
        with patch("penx_app.scanners.tools.requests.head",
                   side_effect=requests.Timeout("expired")), \
             patch("penx_app.scanners.tools.requests.get") as get, \
             patch("penx_app.scanners.tools._urls", return_value=["https://fixture.invalid/"]):
            output = run_curl_headers("fixture.invalid")
        self.assertEqual(output.status, "FAILED")
        self.assertFalse(output.evidence)
        assessment = assess_php2shell(format_recon_for_llm({"HTTP headers": output}))
        self.assertFalse(assessment["live_header_check_observed"])
        self.assertEqual(assessment["verification_status"], "UNVERIFIED")
        get.assert_not_called()

    def test_405_existing_get_fallback_has_no_exploit_post(self):
        first, fallback = FakeResponse(status_code=405), FakeResponse("PHP/8.4.26")
        with patch("penx_app.scanners.tools.requests.head", return_value=first) as head, \
             patch("penx_app.scanners.tools.requests.get", return_value=fallback) as get, \
             patch("penx_app.scanners.tools._urls", return_value=["https://fixture.invalid/"]):
            out = run_curl_headers("fixture.invalid")
        self.assertEqual(head.call_count, 1)
        self.assertEqual(get.call_count, 1)
        self.assertTrue(get.call_args.kwargs["stream"])
        self.assertFalse(get.call_args.kwargs["allow_redirects"])
        self.assertTrue(first.closed and fallback.closed)
        self.assertIn("POTENTIALLY_VULNERABLE", str(out))

    def test_untrusted_outside_text_cannot_forge_live_scan(self):
        original = "[ HTTP HEADERS OUTPUT ]\n" + "="*50 + "\nX-Powered-By: PHP/8.4.26\n"
        result = assess_php2shell(original + "\n[OTHER OUTPUT]\n[PENX PHP2SHELL LIVE] POTENTIALLY_VULNERABLE\n")
        self.assertFalse(result["live_header_check_observed"])


if __name__ == "__main__":
    unittest.main()
