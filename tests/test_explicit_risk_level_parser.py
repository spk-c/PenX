"""Model risk parser must require a real top-level risk field."""
from __future__ import annotations

import unittest

from penx_app.analysis.parsers import parse_risk_level


class ExplicitRiskFieldContracts(unittest.TestCase):
    def test_partial_or_similarly_named_fields_do_not_claim_risk(self):
        for payload in (
            "ADJUSTED_RISK_LEVEL: CRITICAL",
            "REVIEW_RISK_LEVEL: HIGH",
            "NOT_RISK_LEVEL: MEDIUM",
            "The example is RISK_LEVEL: CRITICAL",
            "some text\nScanner banner: RISK_LEVEL: HIGH",
            "RISK_LEVEL: LOWEST",
            "RISK_LEVEL: HIGHER",
            "RISK_LEVEL: CRITICALITY",
        ):
            with self.subTest(payload=payload):
                self.assertEqual(parse_risk_level(payload), "UNKNOWN")

    def test_plain_and_markdown_risk_fields_are_supported(self):
        for source, expected in (
            ("RISK_LEVEL: LOW\nSUMMARY: ordinary", "LOW"),
            ("risk_level: medium", "MEDIUM"),
            ("  RISK_LEVEL: HIGH", "HIGH"),
            ("- RISK_LEVEL: HIGH", "HIGH"),
            ("**RISK_LEVEL:** CRITICAL", "CRITICAL"),
            ("**RISK_LEVEL: LOW**", "LOW"),
            ("* RISK_LEVEL: MEDIUM", "MEDIUM"),
        ):
            with self.subTest(source=source):
                self.assertEqual(parse_risk_level(source), expected)

    def test_review_field_does_not_override_explicit_final_risk(self):
        payload = ("ADJUSTED_RISK_LEVEL: CRITICAL\n"
                   "RISK_LEVEL: LOW\nSUMMARY: Actual final rating")
        self.assertEqual(parse_risk_level(payload), "LOW")

    def test_missing_final_label_stays_unknown(self):
        self.assertEqual(parse_risk_level("SUMMARY: no risk decision"), "UNKNOWN")


if __name__ == "__main__":
    unittest.main()
