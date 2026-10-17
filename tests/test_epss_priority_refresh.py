"""Repeated CVE enrichment must not reuse obsolete EPSS scores.

All provider clients are explicitly injected. No external API requests.
"""
from __future__ import annotations

import unittest

from penx_app.intelligence.cve_priority import enrich_priority


CVE = "CVE-2026-12345"


class EpssPriorityRefreshTests(unittest.TestCase):
    def test_previous_high_epss_clears_when_refresh_is_unavailable(self):
        candidates = [{"id": CVE, "cvss_score": 5.0}]
        enriched, _ = enrich_priority(
            candidates,
            epss_lookup=lambda ids: ({
                CVE: {"epss": 0.92, "epss_percentile": 0.98,
                      "epss_date": "2026-10-16", "epss_url": "https://www.first.org/epss/"}
            }, ""),
            kev_lookup=lambda: set(),
        )
        self.assertEqual(enriched[0]["priority_label"], "high-epss")
        result, warnings = enrich_priority(
            candidates, epss_lookup=lambda ids: ({}, "EPSS unavailable; risk score unknown."),
            kev_lookup=lambda: set(),
        )
        self.assertEqual(result[0]["priority_label"], "review")
        self.assertNotIn("epss", result[0])
        self.assertNotIn("epss_percentile", result[0])
        self.assertNotIn("epss_date", result[0])
        self.assertNotIn("epss_url", result[0])
        self.assertIn("EPSS unavailable", " ".join(warnings))

    def test_new_score_replaces_old_score_without_stale_related_fields(self):
        candidate = {
            "id": CVE, "epss": 0.99, "epss_percentile": 0.99,
            "epss_date": "2024-01-01", "epss_url": "old",
        }
        rows, notes = enrich_priority(
            [candidate],
            epss_lookup=lambda _: ({
                CVE: {"epss": 0.01, "epss_percentile": 0.03},
            }, ""),
            kev_lookup=lambda: set(),
        )
        self.assertEqual(notes, [])
        self.assertEqual(rows[0]["epss"], 0.01)
        self.assertEqual(rows[0]["priority_label"], "review")
        self.assertNotIn("epss_date", rows[0])
        self.assertNotIn("epss_url", rows[0])

    def test_cvss_remains_valid_when_epss_lookup_fails(self):
        data, _ = enrich_priority(
            [{"id": CVE, "epss": 0.99, "cvss_score": 9.8}],
            epss_lookup=lambda _: ({}, "offline"),
            kev_lookup=lambda: set(),
        )
        self.assertNotIn("epss", data[0])
        self.assertEqual(data[0]["priority_label"], "high-cvss")
        self.assertEqual(data[0]["cvss_score"], 9.8)

    def test_disabled_enrichment_does_not_mutate_input_fields(self):
        row = {"id": CVE, "epss": 0.51, "priority_label": "high-epss"}
        output, notes = enrich_priority([row], enabled=False)
        self.assertEqual(notes, [])
        self.assertEqual(output[0], row)
        self.assertEqual(row["epss"], 0.51)

    def test_kev_refresh_is_unaffected_by_epss_clearing(self):
        records = [{"id": CVE, "epss": 0.94, "kev_status": "not-listed"}]
        rows, notes = enrich_priority(
            records, epss_lookup=lambda _: ({}, "offline"),
            kev_lookup=lambda: {CVE},
        )
        self.assertEqual(notes, ["offline"])
        self.assertEqual(rows[0]["kev_status"], "listed")
        self.assertEqual(rows[0]["priority_label"], "known-exploited")
        self.assertNotIn("epss", rows[0])


if __name__ == "__main__":
    unittest.main()
