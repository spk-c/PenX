"""HTTP lifecycle tests for external advisory/catalogue adapters.

Only mocked providers are used, including the rate-limit retry path.
"""
import unittest
from unittest.mock import Mock, patch

import requests

from penx_app.intelligence import cve_engine, cve_priority, vendor_status
from penx_app.intelligence.cve_observations import parse_explicit_packages

CVE = "CVE-2024-6387"


def response(body, *, status=200, retry_after="0"):
    fake = Mock()
    fake.status_code = status
    fake.headers = {"Retry-After": retry_after}
    fake.json.return_value = body
    return fake


class AdvisoryConnectionTests(unittest.TestCase):
    def test_nvd_rate_limit_closes_both_responses(self):
        initial = response({}, status=429)
        final = response({"totalResults": 0, "vulnerabilities": []})
        client = Mock(side_effect=[initial, final])
        with patch.object(cve_engine.time, "sleep") as pause:
            result = cve_engine._get(
                cve_engine.NVD, params={}, headers={}, http_get=client)
        self.assertEqual(result["totalResults"], 0)
        pause.assert_called_once_with(0)
        initial.close.assert_called_once()
        final.close.assert_called_once()

    def test_nvd_invalid_json_closes_response(self):
        fake = response({})
        fake.json.side_effect = ValueError("invalid JSON")
        with self.assertRaises(ValueError):
            cve_engine._get(cve_engine.NVD, params={}, headers={},
                            http_get=lambda *a, **kw: fake)
        fake.close.assert_called_once()

    def test_osv_bounded_request_closes_response(self):
        package = parse_explicit_packages("pkg:pypi/requests@2.31.0")[0]
        fake = response({"vulns": []})
        result, warning = cve_engine.osv_candidates(
            package, http_post=lambda *a, **kw: fake)
        self.assertEqual((result, warning), ([], ""))
        fake.close.assert_called_once()

    def test_osv_http_failure_closes_response(self):
        package = parse_explicit_packages("pkg:pypi/requests@2.31.0")[0]
        fake = response({})
        fake.raise_for_status.side_effect = requests.HTTPError("429")
        rows, warning = cve_engine.osv_candidates(
            package, http_post=lambda *a, **kw: fake)
        self.assertEqual(rows, [])
        self.assertTrue(warning)
        fake.close.assert_called_once()

    def test_epss_success_and_invalid_response_close(self):
        first = response({"data": [{
            "cve": CVE, "epss": "0.5", "percentile": "0.7",
            "date": "2026-10-16",
        }]})
        values, warning = cve_priority.fetch_epss(
            [CVE], http_get=lambda *a, **kw: first)
        self.assertFalse(warning)
        self.assertAlmostEqual(values[CVE]["epss"], 0.5)
        first.close.assert_called_once()

        malformed = response([])
        values, warning = cve_priority.fetch_epss(
            [CVE], http_get=lambda *a, **kw: malformed)
        self.assertEqual(values, {})
        self.assertTrue(warning)
        malformed.close.assert_called_once()

    def test_vendor_advisory_http_failure_closes_connection(self):
        fake = response({})
        fake.raise_for_status.side_effect = requests.Timeout("offline")
        self.assertIsNone(vendor_status._advisory_json(
            "https://example.invalid", http_get=lambda *a, **kw: fake))
        fake.close.assert_called_once()

    def test_vendor_advisory_success_closes_connection(self):
        fake = response({"status": "test"})
        self.assertEqual(vendor_status._advisory_json(
            "https://example.invalid", http_get=lambda *a, **kw: fake),
            {"status": "test"})
        fake.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
