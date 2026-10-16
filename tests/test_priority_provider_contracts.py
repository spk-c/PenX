"""Offline CVE priority provider contracts; no production network requests."""
from __future__ import annotations

import unittest
from unittest.mock import Mock, patch

import requests

from penx_app.intelligence import cve_priority as priority


def response(data):
    res = Mock()
    res.json.return_value = data
    res.raise_for_status.return_value = None
    return res


class PriorityProviderContracts(unittest.TestCase):
    CVE = "CVE-2026-12345"

    def test_unsupported_cvss_payloads_never_crash_or_invent_severity(self):
        for payload in (
            {"cvssMetricV31": "not-a-list"},
            {"cvssMetricV31": ["invalid", None, 99]},
            {"cvssMetricV31": [{"cvssData": "not-a-dict"}]},
            {"cvssMetricV31": [{"cvssData": {"baseScore": True}}]},
            {"cvssMetricV31": [{"cvssData": {"baseScore": float("inf")}}]},
        ):
            with self.subTest(payload=payload):
                self.assertEqual(priority.extract_cvss(payload), {})
        good = {"cvssMetricV31": [
            {"type": "Secondary", "cvssData": {"baseScore": 6.5}},
            {"type": "Primary", "cvssData": {"baseScore": 9.1,
                                            "version": "3.1"}},
            "invalid",
        ]}
        self.assertEqual(priority.extract_cvss(good)["cvss_score"], 9.1)

    def test_epss_request_is_scoped_bounded_and_custom_client_never_calls_network(self):
        seen = []
        def fake(url, **kwargs):
            seen.append((url, kwargs))
            return response({"data": [
                {"cve": self.CVE, "epss": "0.71",
                 "percentile": "0.93", "date": "2026-10-16"},
                {"cve": "CVE-2024-0001", "epss": "0.99",
                 "percentile": "0.99"},
            ]})
        with patch.object(priority.requests, "get",
                          side_effect=AssertionError("real network")):
            found, warning = priority.fetch_epss(
                [self.CVE, self.CVE, "invalid"], http_get=fake)
        self.assertEqual(warning, "")
        self.assertEqual(list(found), [self.CVE])
        self.assertAlmostEqual(found[self.CVE]["epss"], 0.71)
        self.assertEqual(seen, [(priority.EPSS_URL, {
            "params": {"cve": self.CVE}, "timeout": (3, 9),
            "allow_redirects": False,
        })])

    def test_malformed_epss_root_is_unknown_not_empty_success(self):
        for payload in (None, [], "invalid", {}, {"data": "bad"}):
            with self.subTest(payload=payload):
                found, warning = priority.fetch_epss(
                    [self.CVE], http_get=lambda *_a, **_kw: response(payload))
                self.assertEqual(found, {})
                self.assertIn("unavailable", warning)

    def test_incorrect_epss_rows_are_warned_and_skipped(self):
        found, warning = priority.fetch_epss(
            [self.CVE], http_get=lambda *_a, **_kw: response({
                "data": ["wrong", {"cve": self.CVE, "epss": "NaN",
                                   "percentile": "0.7"},
                         {"cve": "CVE-2024-0001", "epss": "0.8",
                          "percentile": "0.99"}]
            }))
        self.assertEqual(found, {})
        self.assertIn("malformed", warning)

    def test_timeout_never_leaks_credentials_or_raises(self):
        fake = Mock(side_effect=requests.Timeout("token=FAKE_SECRET"))
        found, warning = priority.fetch_epss([self.CVE], http_get=fake)
        self.assertEqual(found, {})
        self.assertIn("unavailable", warning)
        self.assertNotIn("FAKE_SECRET", warning)

    def test_injecting_both_priority_sources_does_not_contact_default_clients(self):
        seen = []
        def epss(ids):
            seen.append(("epss", ids))
            return ({self.CVE: {"epss": 0.8, "epss_percentile": 0.9}}, "")
        def kev():
            seen.append(("kev", None))
            return {self.CVE}
        data = [{"id": self.CVE, "cvss_score": 5}]
        with patch.object(priority, "fetch_epss",
                          side_effect=AssertionError("default EPSS")):
            with patch.object(priority, "load_cisa_kev",
                              side_effect=AssertionError("default KEV")):
                result, warnings = priority.enrich_priority(
                    data, epss_lookup=epss, kev_lookup=kev)
        self.assertIs(result, data)
        self.assertEqual(warnings, [])
        self.assertEqual(result[0]["priority_label"], "known-exploited")
        self.assertEqual(seen, [("epss", [self.CVE]), ("kev", None)])

    def test_injected_source_errors_are_unknown_without_forged_score(self):
        data = [{"id": self.CVE, "cvss_score": 4.0}]
        result, warnings = priority.enrich_priority(
            data,
            epss_lookup=Mock(side_effect=requests.Timeout("API secret")),
            kev_lookup=Mock(side_effect=requests.ConnectionError("API secret")),
        )
        self.assertEqual(result[0]["kev_status"], "unknown")
        self.assertEqual(result[0]["priority_label"], "review")
        self.assertNotIn("epss", result[0])
        self.assertTrue(any("EPSS unavailable" in line for line in warnings))
        self.assertTrue(any("KEV unavailable" in line for line in warnings))
        self.assertNotIn("API secret", str(warnings))

    def test_invalid_injected_scores_cannot_change_priority(self):
        for bad in ("0.9", float("nan"), float("inf"), -0.1, True, None):
            with self.subTest(score=bad):
                data = [{"id": self.CVE, "cvss_score": 4.0}]
                updated, warnings = priority.enrich_priority(
                    data,
                    epss_lookup=lambda ids: ({
                        self.CVE: {"epss": bad, "epss_percentile": 0.9}
                    }, ""),
                    kev_lookup=lambda: None,
                )
                self.assertNotIn("epss", updated[0])
                self.assertEqual(updated[0]["priority_label"], "review")
                self.assertEqual(updated[0]["kev_status"], "unknown")
                self.assertTrue(any("EPSS unavailable" in warning
                                    for warning in warnings))

    def test_disabled_priority_skips_every_provider(self):
        epss = Mock(side_effect=AssertionError("disabled"))
        kev = Mock(side_effect=AssertionError("disabled"))
        candidates = [{"id": self.CVE}]
        updated, warnings = priority.enrich_priority(
            candidates, enabled=False, epss_lookup=epss, kev_lookup=kev)
        self.assertIs(updated, candidates)
        self.assertEqual(warnings, [])
        epss.assert_not_called()
        kev.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
