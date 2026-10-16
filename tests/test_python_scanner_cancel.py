"""Cooperative cancellation of blocking Python network scanner adapters.

These tests perform no DNS, HTTP, WHOIS or TLS network traffic.
"""
from __future__ import annotations

import sys
import threading
import types
import unittest
from unittest.mock import Mock, patch

from penx_app.application.scanner_execution import run_selected_structured
from penx_app.domain.scan_models import ScanRequest
from penx_app.scanners import tools


class PythonScannerCancellationTests(unittest.TestCase):
    def test_precancelled_python_network_adapters_skip_all_io(self):
        token = threading.Event()
        token.set()
        with patch.object(tools, "_host", side_effect=AssertionError("host normalized")), \
             patch.object(tools, "_urls", side_effect=AssertionError("urls collected")), \
             patch.object(tools, "web_endpoint", side_effect=AssertionError("TLS target parsed")), \
             patch.object(tools.requests, "head", side_effect=AssertionError("HTTP request")):
            for function in (tools.run_whois, tools.run_curl_headers,
                             tools.run_dig, tools.run_tls_check):
                with self.subTest(adapter=function.__name__):
                    result = function("fixture.invalid", cancel_event=token)
                    self.assertEqual(result.status, "PARTIAL")
                    self.assertFalse(result.evidence)

    def test_whois_completed_response_is_not_evidence_after_cancel(self):
        token = threading.Event()
        def fake_whois(_host):
            token.set()
            return {"private": "SHOULD-NOT-BE-EXPORTED"}
        mocked = types.SimpleNamespace(whois=fake_whois)
        with patch.object(tools, "_host", return_value="fixture.invalid"), \
             patch.dict(sys.modules, {"whois": mocked}):
            result = tools.run_whois("fixture.invalid", cancel_event=token)
        self.assertEqual(result.status, "PARTIAL")
        self.assertFalse(result.evidence)
        self.assertNotIn("SHOULD-NOT-BE-EXPORTED", str(result))

    def test_http_head_cancel_never_starts_second_get(self):
        token = threading.Event()
        head_response = Mock(status_code=405)
        def head(*_args, **_kwargs):
            token.set()
            return head_response
        with patch.object(tools, "_urls", return_value=[
                "https://fixture.invalid", "http://fixture.invalid"]), \
             patch.object(tools.requests, "head", side_effect=head) as fetch_head, \
             patch.object(tools.requests, "get",
                          side_effect=AssertionError("fallback GET after cancel")) as fetch_get:
            result = tools.run_curl_headers("fixture.invalid", cancel_event=token)
        self.assertEqual(result.status, "PARTIAL")
        self.assertFalse(result.evidence)
        fetch_head.assert_called_once()
        fetch_get.assert_not_called()
        head_response.close.assert_called_once()

    def test_dns_cancel_after_first_record_skips_other_lookups(self):
        import dns.resolver
        token = threading.Event()
        def resolve(*_args, **_kwargs):
            token.set()
            return ["192.0.2.123"]
        with patch.object(tools, "_host", return_value="fixture.invalid"), \
             patch.object(dns.resolver, "resolve", side_effect=resolve) as lookup:
            result = tools.run_dig("fixture.invalid", cancel_event=token)
        self.assertEqual(result.status, "PARTIAL")
        self.assertFalse(result.evidence)
        lookup.assert_called_once()

    def test_tls_cancel_after_timeout_does_not_retry(self):
        import socket
        token = threading.Event()
        def timeout(*_args, **_kwargs):
            token.set()
            raise socket.timeout("synthetic first timeout")
        with patch.object(tools, "web_endpoint",
                          return_value="https://fixture.invalid"), \
             patch.object(socket, "create_connection",
                          side_effect=timeout) as connect:
            result = tools.run_tls_check("fixture.invalid", cancel_event=token)
        self.assertEqual(result.status, "PARTIAL")
        self.assertFalse(result.evidence)
        connect.assert_called_once()

    def test_dispatch_cancelled_http_does_not_dispatch_queued_dns(self):
        token = threading.Event()
        head_response = Mock(status_code=200, url="https://fixture.invalid")
        head_response.headers = {}
        def head(*_args, **_kwargs):
            token.set()
            return head_response
        with patch.object(tools, "_urls", return_value=["https://fixture.invalid"]), \
             patch.object(tools.requests, "head", side_effect=head), \
             patch.object(tools, "run_dig",
                          side_effect=AssertionError("queued adapter started")):
            result = run_selected_structured(
                ScanRequest("fixture.invalid", ("4", "5")),
                menu={"4": ("HTTP headers", tools.run_curl_headers),
                      "5": ("DNS", tools.run_dig)}, cancel_event=token)
        self.assertEqual([row.status for row in result.results],
                         ["PARTIAL", "PARTIAL"])
        self.assertFalse(result.has_evidence)


if __name__ == "__main__":
    unittest.main()
