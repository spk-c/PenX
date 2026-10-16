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

    def test_bad_target_never_reaches_nmap_adapter(self):
        with patch("penx_app.scanners.tools._executable",
                   side_effect=AssertionError("must not launch scanner")):
            result = run_nmap("example.test:garbage")
        self.assertEqual(result.status, "FAILED")
        self.assertFalse(result.evidence)


if __name__ == "__main__":
    unittest.main()
