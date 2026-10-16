"""Bounded CVE source verification across repeated findings (no live network)."""
from __future__ import annotations

import unittest
from unittest.mock import Mock, patch

from penx_app.intelligence.source_verification import verify_findings


CVE_A = "CVE-2024-6387"
CVE_B = "CVE-2023-48795"
CVE_C = "CVE-2022-12345"


def finding(cve: str) -> dict:
    return {
        "vuln_name": cve,
        "description": "Synthetic advisory review",
        "evidence": "No scanner quote available",
        "confidence": "possible",
    }


class CveAssessmentDedupTests(unittest.TestCase):
    def test_repeated_cve_only_uses_each_provider_once(self):
        nvd = Mock(return_value="listed")
        applicability = Mock(return_value="unknown")
        kev = Mock(return_value={CVE_A})
        rows = [finding(CVE_A) for _ in range(45)]
        with patch("penx_app.intelligence.source_verification.requests.get",
                   side_effect=AssertionError("Live HTTP must not run")):
            result = verify_findings(
                rows, "Synthetic scanner output", max_lookups=1,
                nvd_lookup=nvd, applicability_lookup=applicability,
                kev_loader=kev,
            )
        self.assertEqual(len(result), 45)
        nvd.assert_called_once_with(CVE_A, api_key="")
        applicability.assert_called_once_with(
            CVE_A, "Synthetic scanner output", api_key="")
        kev.assert_called_once_with()
        self.assertTrue(all("NVD listed" in row["description"] for row in rows))
        self.assertTrue(all("CISA KEV listed" in row["description"] for row in rows))

    def test_unique_cve_limit_does_not_requery_earlier_ids(self):
        nvd = Mock(return_value="not-listed")
        applicability = Mock(return_value="no-match")
        kev = Mock(return_value=set())
        rows = [finding(CVE_A), finding(CVE_B), finding(CVE_C),
                finding(CVE_A), finding(CVE_B)]
        verify_findings(
            rows, "Fixture", max_lookups=2, nvd_lookup=nvd,
            applicability_lookup=applicability, kev_loader=kev,
        )
        self.assertEqual(nvd.call_count, 2)
        self.assertEqual(applicability.call_count, 2)
        self.assertIn("Additional CVEs skipped", rows[2]["description"])
        self.assertIn("NVD not-listed", rows[3]["description"])
        self.assertIn("NVD not-listed", rows[4]["description"])
        kev.assert_called_once()

    def test_two_assessments_use_separate_caches(self):
        nvd = Mock(side_effect=["listed", "unavailable"])
        applicability = Mock(return_value="unknown")
        for _ in range(2):
            verify_findings(
                [finding(CVE_A)], "Fixture",
                nvd_lookup=nvd, applicability_lookup=applicability,
                kev_loader=lambda: None,
            )
        self.assertEqual(nvd.call_count, 2)
        self.assertEqual(applicability.call_count, 2)


if __name__ == "__main__":
    unittest.main()
