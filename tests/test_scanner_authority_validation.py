"""Reject ambiguous or malformed scanner authorities before launching tools."""
from __future__ import annotations

import unittest
from unittest.mock import patch

from penx_app.scanners.scanner_targets import normalize_host, normalize_web_target
from penx_app.scanners.tools import run_nmap


class ScannerAuthorityValidationTests(unittest.TestCase):
    def test_bad_bare_ports_must_not_silently_select_hostname(self):
        for text in (
            "example.test:garbage",
            "example.test:",
            "example.test:0",
            "example.test:65536",
            "example.test:443evil",
        ):
            with self.subTest(text=text), self.assertRaises(ValueError):
                normalize_host(text)

    def test_bad_bracketed_ipv6_must_not_silently_select_localhost(self):
        for text in (
            "[::1]evil",
            "[::1]:garbage",
            "[::1]:0",
            "[::1]:65536",
            "[::1]:",
            "[example.test]:443",
        ):
            with self.subTest(text=text), self.assertRaises(ValueError):
                normalize_host(text)

    def test_malformed_url_ports_and_credentials_are_refused(self):
        for text in (
            "https://example.test:garbage/",
            "http://example.test:65536/path",
            "https://example.test:/",
            "https://user:password@example.test/",
            "https://example.test/#fragment",
        ):
            with self.subTest(text=text), self.assertRaises(ValueError):
                normalize_host(text)

    def test_known_valid_authorities_still_work(self):
        expected = {
            "example.test:8443": "example.test",
            "[::1]:443": "::1",
            "[2001:DB8::1]": "2001:db8::1",
            "2001:db8::1": "2001:db8::1",
            "https://example.test:8443/path": "example.test",
            "example.test/path": "example.test",
        }
        for text, host in expected.items():
            with self.subTest(text=text):
                self.assertEqual(normalize_host(text), host)
        self.assertEqual(normalize_web_target("example.test:8443"), "example.test:8443")
        self.assertEqual(normalize_web_target("[2001:db8::1]:443"), "[2001:db8::1]:443")

    def test_bracketed_netloc_and_ipv6_port_regressions(self):
        # Regression for PR #113's exact-netloc check: a valid bracketed IPv6
        # plus an explicit port still normalizes to the bare address (the
        # exact match must not over-reject the case the old startswith()
        # check already handled).
        self.assertEqual(normalize_host("[2001:db8::1]:8080"), "2001:db8::1")
        self.assertEqual(normalize_host("[fe80::A:B:C:D:E]:1337"),
                         "fe80::a:b:c:d:e")
        self.assertEqual(normalize_host("[2001:db8::1]"), "2001:db8::1")
        # The PR's actual fix: any text after the closing bracket is now
        # rejected instead of being silently scanned.
        with self.assertRaises(ValueError):
            normalize_host("[2001:db8::1]junk")
        # An invalid port on a bracketed netloc is still refused.
        with self.assertRaisesRegex(ValueError, "Invalid"):
            normalize_host("[2001:db8::1]:443junk")
        # Plain host:port still drops the port for host scanners; the port is
        # reconstructed only by normalize_web_target / target_urls.
        self.assertEqual(normalize_host("example.test:443"), "example.test")
        # NOTE: a non-bracketed "ip6:port" (e.g. 2001:db8::1:8080) is itself
        # a syntactically valid bare IPv6 (absorbed as a different address), so
        # it is deliberately left to the pre-existing fall-through behavior.
        # See the Deep-Audit report for the remaining ambiguity risk.

    def test_bad_target_never_reaches_nmap_adapter(self):
        with patch("penx_app.scanners.tools._executable",
                   side_effect=AssertionError("must not launch scanner")):
            result = run_nmap("example.test:garbage")
        self.assertEqual(result.status, "FAILED")
        self.assertFalse(result.evidence)


if __name__ == "__main__":
    unittest.main()
