"""Offline tests: WhatWeb fingerprints, network-query gating and diagnostics."""
import unittest
from unittest.mock import patch, Mock

from penx_app.intelligence.wordpress_advisories import observed_plugins, research_plugins, format_plugin_report


class WordpressAdvisoryTests(unittest.TestCase):
    SAMPLE = ("https://www.example.test [200 OK] MetaGenerator[Elementor 4.3.5; features: x], "
              "PoweredBy[FlyingPress]")

    def test_fingerprint_detects_both_plugins_without_guessing_version(self):
        result = observed_plugins(self.SAMPLE)
        self.assertEqual([(x["slug"], x["version"]) for x in result],
                         [("elementor", "4.3.5"), ("flyingpress", "")])

    def test_no_fingerprint_no_api_call(self):
        with patch("penx_app.intelligence.wordpress_advisories.requests.get") as request:
            report = research_plugins("WordPress", token="dummy")
            request.assert_not_called()
        self.assertEqual(report["checks"][0]["status"], "skipped")

    def test_no_request_when_disabled(self):
        with patch("penx_app.intelligence.wordpress_advisories.requests.get") as request:
            report = research_plugins(self.SAMPLE, token="dummy", enabled=False)
            request.assert_not_called()
        self.assertEqual(report["checks"][0]["status"], "disabled")

    def test_authenticated_queries_and_unknown_version(self):
        response = Mock()
        response.json.return_value = [{
            "cve_id": "CVE-2026-12345",
            "html_url": "https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
            "vulnerabilities": [],
        }]
        with patch("penx_app.intelligence.wordpress_advisories.requests.get", return_value=response) as request:
            report = research_plugins(self.SAMPLE, token="test-token")
        self.assertEqual(request.call_count, 2)
        self.assertEqual(request.call_args.kwargs["headers"]["Authorization"], "Bearer test-token")
        self.assertEqual(report["candidates"][1]["status"], "version-unknown")
        diag = format_plugin_report(report, nvd_key_configured=True, github_key_configured=True)
        self.assertIn("GitHub Advisory queried", diag)
        self.assertNotIn("test-token", diag)

    def test_unavailable_is_not_empty_success(self):
        import requests
        with patch("penx_app.intelligence.wordpress_advisories.requests.get",
                   side_effect=requests.Timeout("simulated")):
            report = research_plugins(self.SAMPLE)
        self.assertTrue(all(x["status"] == "unavailable" for x in report["checks"]))
        self.assertEqual(report["candidates"], [])


if __name__ == "__main__":
    unittest.main()
