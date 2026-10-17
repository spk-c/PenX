"""Reviewer evidence must not grow with scanner section count.

All text is synthetic. No scanner, model, network or database is used.
"""
from __future__ import annotations

import unittest

from penx_app.analysis.assessment_quality import (
    MAX_REVIEW_CHARS, MAX_REVIEW_SECTIONS, review_evidence,
)


class BoundedReviewerEvidenceTests(unittest.TestCase):
    def test_ordinary_scanner_sections_keep_output_and_attribution(self):
        raw = (
            "[NMAP OUTPUT]\n443/tcp open https\n\n"
            "[NIKTO OUTPUT]\nHTTP/1.1 200 OK\n"
        )
        result = review_evidence(raw)
        self.assertIn("[NMAP OUTPUT]", result)
        self.assertIn("443/tcp open https", result)
        self.assertIn("[NIKTO OUTPUT]", result)
        self.assertIn("HTTP/1.1 200 OK", result)
        self.assertNotIn("TRUNCATED SCAN EVIDENCE", result)

    def test_hundreds_of_sections_keep_first_and_last_with_omission_warning(self):
        raw = "".join(
            f"[SCANNER{i:03d} OUTPUT]\n"
            + (("ENDPOINT 443/tcp open https\n" if i == 119 else
                "PORT 22/tcp open ssh\n" if i == 0 else "filler text\n")
               + "A" * 1000 + "\n")
            for i in range(120)
        )
        result = review_evidence(raw)
        self.assertLessEqual(len(result), MAX_REVIEW_CHARS)
        self.assertIn("72 scanner section(s) omitted", result)
        self.assertIn("[SCANNER000 OUTPUT]", result)
        self.assertIn("[SCANNER119 OUTPUT]", result)
        self.assertNotIn("[SCANNER060 OUTPUT]", result)
        self.assertIn("original raw scan retained", result)

    def test_total_budget_applies_across_maximum_selected_sections(self):
        raw = "".join(
            f"[SCANNER{i:03d} OUTPUT]\n"
            + ("443/tcp open https\n" + "X" * 2900 + "\n")
            for i in range(MAX_REVIEW_SECTIONS)
        )
        result = review_evidence(raw)
        self.assertLessEqual(len(result), MAX_REVIEW_CHARS)
        self.assertIn("TRUNCATED SCAN EVIDENCE", result)
        self.assertIn("[SCANNER000 OUTPUT]", result)
        self.assertIn("[SCANNER047 OUTPUT]", result)
        self.assertIn("does NOT establish its absence", result)

    def test_untrusted_per_source_hint_cannot_bypass_global_budget(self):
        raw = "".join(
            "[NMAP OUTPUT]\n" + "exposed port 80/tcp open http\n" * 300
            for _ in range(20)
        )
        result = review_evidence(raw, per_source=10**10)
        self.assertLessEqual(len(result), MAX_REVIEW_CHARS)

    def test_nmap_xml_appendix_still_is_not_reviewer_proof(self):
        raw = (
            "[NMAP OUTPUT]\n22/tcp open ssh\n"
            "[NMAP STRUCTURED XML]\n<synthetic>secret</synthetic>\n"
            "[WHATWEB OUTPUT]\nWordPress 6.0\n"
        )
        result = review_evidence(raw)
        self.assertIn("22/tcp open ssh", result)
        self.assertIn("WordPress 6.0", result)
        self.assertNotIn("<synthetic>secret</synthetic>", result)

    def test_no_heading_still_stays_bounded(self):
        result = review_evidence("unlabelled raw\n" * 100000)
        self.assertLessEqual(len(result), MAX_REVIEW_CHARS)
        self.assertIn("evidence omitted for review", result)


if __name__ == "__main__":
    unittest.main()
