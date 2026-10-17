"""CVE sorting must not trust numeric types and bounds from external adapters."""
from __future__ import annotations

import unittest

from penx_app.intelligence.cve_priority import enrich_priority


CVE = "CVE-2026-12345"


class CvePriorityInvalidScoresTests(unittest.TestCase):
    def enrich(self, rows):
        return enrich_priority(
            rows,
            epss_lookup=lambda _ids: ({}, ""),
            kev_lookup=lambda: set(),
        )

    def test_invalid_cvss_values_never_crash_or_produce_critical_priority(self):
        for value in ("9.8", None, True, False, [], {}, float("nan"),
                      float("inf"), float("-inf"), -2, 11):
            with self.subTest(value=repr(value)):
                rows, errors = self.enrich([{"id": CVE, "cvss_score": value}])
                self.assertEqual(errors, [])
                self.assertEqual(rows[0]["priority_label"], "review")

    def test_malformed_scores_do_not_crash_sorting_of_multiple_candidates(self):
        cases = [
            {"id": "CVE-2026-11111", "cvss_score": "10"},
            {"id": "CVE-2026-22222", "cvss_score": 9.8},
            {"id": "CVE-2026-33333", "cvss_score": {"base": 9.9}},
            {"id": "CVE-2026-44444", "cvss_score": float("nan")},
        ]
        result, errors = self.enrich(cases)
        self.assertEqual(errors, [])
        self.assertEqual(result[0]["id"], "CVE-2026-22222")
        self.assertEqual(result[0]["priority_label"], "high-cvss")
        self.assertTrue(all(item["priority_label"] == "review"
                            for item in result[1:]))

    def test_unsupported_probability_does_not_outrank_valid_cvss(self):
        rows, errors = self.enrich([
            {"id": "CVE-2026-22222", "epss": "0.99", "cvss_score": 2},
            {"id": "CVE-2026-44444", "epss": float("inf"), "cvss_score": 2},
            {"id": "CVE-2026-33333", "cvss_score": 9.2},
        ])
        self.assertEqual(errors, [])
        self.assertEqual(rows[0]["id"], "CVE-2026-33333")
        self.assertEqual(rows[0]["priority_label"], "high-cvss")
        self.assertTrue(all(item["priority_label"] == "review"
                            for item in rows[1:]))

    def test_valid_scores_and_kev_membership_keep_existing_priority(self):
        rows, warnings = enrich_priority(
            [{"id": CVE, "cvss_score": 9.8}],
            epss_lookup=lambda _ids: ({
                CVE: {"epss": 0.77, "epss_percentile": 0.85},
            }, ""),
            kev_lookup=lambda: {CVE},
        )
        self.assertEqual(warnings, [])
        self.assertEqual(rows[0]["priority_label"], "known-exploited")
        self.assertEqual(rows[0]["epss"], 0.77)


if __name__ == "__main__":
    unittest.main()
