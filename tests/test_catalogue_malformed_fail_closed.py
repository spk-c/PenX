"""Offline malformed-provider and response-lifetime regressions.

Every HTTP response is injected. No scanner, network or real DB is accessed.
"""
from __future__ import annotations

import unittest
from unittest.mock import Mock, patch

from penx_app.intelligence import source_verification as sources

CVE = "CVE-2024-6387"


def fake_response(payload):
    response = Mock()
    response.json.return_value = payload
    return response


class CatalogueFailClosedTests(unittest.TestCase):
    def setUp(self):
        sources._nvd_cache.clear()
        sources._kev_cache = None

    def test_nvd_missing_or_malformed_records_are_not_a_negative_lookup(self):
        payloads = (
            None, [], {}, {"vulnerabilities": None},
            {"vulnerabilities": "bad"},
            {"vulnerabilities": [None]},
            {"vulnerabilities": [{"cve": "bad"}]},
            {"vulnerabilities": [{"cve": {"id": None}}]},
        )
        for payload in payloads:
            with self.subTest(payload=payload):
                response = fake_response(payload)
                self.assertEqual(sources.lookup_nvd(
                    CVE, get=lambda *args, **kwargs: response), "unavailable")
                response.close.assert_called_once()
                self.assertNotIn(CVE, sources._nvd_cache)

    def test_nvd_valid_empty_records_are_not_listed(self):
        response = fake_response({"vulnerabilities": []})
        self.assertEqual(sources.lookup_nvd(
            CVE, get=lambda *args, **kwargs: response), "not-listed")
        response.close.assert_called_once()

    def test_nvd_valid_matching_cve_is_listed(self):
        response = fake_response({"vulnerabilities": [{"cve": {"id": CVE}}]})
        self.assertEqual(sources.lookup_nvd(
            CVE, get=lambda *args, **kwargs: response), "listed")
        response.close.assert_called_once()

    def test_nvd_applicability_malformed_envelopes_fail_closed(self):
        with patch("penx_app.intelligence.cve_observations.parse_nmap_services",
                   return_value=[object()]):
            for payload in ({}, [], {"vulnerabilities": [42]},
                            {"vulnerabilities": [{"cve": None}]}):
                with self.subTest(payload=payload):
                    response = fake_response(payload)
                    result = sources.verify_nvd_applicability(
                        CVE, "synthetic versioned fixture",
                        get=lambda *args, **kwargs: response)
                    self.assertEqual(result, "unavailable")
                    response.close.assert_called_once()

    def test_kev_malformed_is_unknown_never_empty_verified_set(self):
        for payload in ({}, [], {"vulnerabilities": None},
                        {"vulnerabilities": "invalid"},
                        {"vulnerabilities": [{"cveID": None}]},
                        {"vulnerabilities": ["invalid record"]}):
            with self.subTest(payload=payload):
                response = fake_response(payload)
                self.assertIsNone(sources.load_cisa_kev(
                    get=lambda *args, **kwargs: response))
                response.close.assert_called_once()
                self.assertIsNone(sources._kev_cache)

    def test_kev_valid_fixture_remains_supported(self):
        response = fake_response({"vulnerabilities": [{"cveID": CVE}]})
        self.assertEqual(sources.load_cisa_kev(
            get=lambda *args, **kwargs: response), {CVE})
        response.close.assert_called_once()

    def test_http_errors_also_close_connections(self):
        for function, url in (
            (sources.lookup_nvd, CVE),
            (sources.verify_nvd_applicability, CVE),
            (sources.load_cisa_kev, None),
        ):
            with self.subTest(function=function.__name__):
                response = fake_response(None)
                response.raise_for_status.side_effect = ValueError("broken response")
                with patch("penx_app.intelligence.cve_observations.parse_nmap_services",
                           return_value=[object()]):
                    if url is None:
                        self.assertIsNone(function(
                            get=lambda *args, **kwargs: response))
                    else:
                        value = function(
                            url, *("synthetic" if False else []),
                            **({"raw_scan": "synthetic"} if function == sources.verify_nvd_applicability else {}),
                            get=lambda *args, **kwargs: response)
                        self.assertIn(value, {"unavailable"})
                response.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
