"""Offline regression tests for scan coverage and version-aware source checks."""
import unittest
from unittest.mock import patch

from penx_app.reporting.scan_coverage import coverage
from penx_app.intelligence.source_verification import verify_nvd_applicability


class CoverageTests(unittest.TestCase):
    def test_nikto_dependency_failure_marks_partial(self):
        raw = ("[ NMAP OUTPUT ]\n80/tcp open http\nNmap done: 1 IP\n"
               "[ NIKTO OUTPUT ]\n[EXIT CODE 1]\nERROR: Required module not found: XML::Writer")
        state = coverage(raw)
        self.assertEqual(state["status"], "PARTIAL")
        self.assertEqual(state["failed"], ["NIKTO"])
        self.assertEqual(state["completed"], ["NMAP"])

    def test_only_selected_tools_count(self):
        raw = "[ NMAP OUTPUT ]\n80/tcp open http\nNmap done:"
        self.assertEqual(coverage(raw)["status"], "COMPLETE")
        self.assertEqual(coverage(raw)["failed"], [])

    def test_unknown_and_passive_coverage(self):
        self.assertEqual(coverage("")["status"], "UNKNOWN")
        self.assertEqual(coverage("", passive_only=True)["status"], "PASSIVE")

    def test_timeout_marks_partial(self):
        self.assertEqual(coverage("[ NIKTO OUTPUT ]\n[!] Timed out after 60s")["status"], "PARTIAL")


class CveVerificationTests(unittest.TestCase):
    def test_unknown_cpe_does_not_request_nvd(self):
        with patch("penx_app.intelligence.source_verification.requests.get") as get:
            result = verify_nvd_applicability("CVE-2026-12345", "PoweredBy[FlyingPress]")
        self.assertIn("unknown", result)
        get.assert_not_called()

    def test_matching_cpe_requires_vendor_review(self):
        from penx_app.intelligence.cve_observations import Product
        product = Product("cpe:2.3:a:example:plugin:4.3.5:*:*:*:*:*:*:*",
                          "plugin", "4.3.5", "443", "https", "fixture")
        payload = {"vulnerabilities": [{"cve": {
            "id": "CVE-2026-12345",
            "configurations": [{"nodes": [{"operator": "OR", "cpeMatch": [{
                "vulnerable": True,
                "criteria": "cpe:2.3:a:example:plugin:*:*:*:*:*:*:*:*",
                "versionStartIncluding": "4.3.0",
                "versionEndIncluding": "4.3.5"
            }]}]}]
        }}]}
        from unittest.mock import Mock
        response = Mock()
        response.json.return_value = payload
        with patch("penx_app.intelligence.cve_observations.parse_nmap_services", return_value=[product]), \
             patch("penx_app.intelligence.source_verification.requests.get", return_value=response):
            result = verify_nvd_applicability("CVE-2026-12345", "fixture")
        self.assertIn("vendor-review", result)


if __name__ == "__main__":
    unittest.main()
