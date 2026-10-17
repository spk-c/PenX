"""Rerunning source checks must not accumulate historical model annotations.

No network requests: source verification clients are injected mocks.
"""
from __future__ import annotations

import copy
import unittest
from unittest.mock import Mock

from penx_app.intelligence.source_verification import verify_findings


FIRST = "CVE-2024-6387"
SECOND = "CVE-2026-12345"


def verify(findings, *, cves=None):
    cves = {FIRST} if cves is None else cves
    return verify_findings(
        findings, "443/tcp open HTTPS",
        nvd_lookup=lambda _cve, **kw: "listed",
        applicability_lookup=lambda _cve, *_a, **kw: "unknown",
        kev_loader=lambda: cves,
    )


class SourceVerificationRepeatabilityTests(unittest.TestCase):
    def test_double_verification_is_idempotent(self):
        finding = {
            "vuln_name": "OpenSSH finding " + FIRST,
            "description": "Review package version",
            "evidence": "443/tcp open HTTPS",
            "confidence": "possible",
        }
        result = verify([finding])
        once = copy.deepcopy(result)
        verify(result)
        self.assertEqual(result, once)
        self.assertEqual(finding["description"].count("Reference checks ("), 1)
        self.assertEqual(finding["description"].count("CISA KEV listed"), 1)

    def test_empty_original_description_is_also_idempotent(self):
        finding = {
            "vuln_name": FIRST, "description": "",
            "evidence": "Not supported evidence", "confidence": "possible",
        }
        verify([finding])
        once = finding["description"]
        verify([finding])
        self.assertEqual(finding["description"], once)

    def test_old_cve_annotations_do_not_retain_removed_identifiers(self):
        finding = {
            "vuln_name": FIRST,
            "description": "A synthetic finding",
            "evidence": "443/tcp open HTTPS",
            "confidence": "possible",
        }
        verify([finding], cves={FIRST})
        finding["vuln_name"] = SECOND
        verify([finding], cves={SECOND})
        self.assertIn(SECOND, finding["description"])
        self.assertNotIn(FIRST, finding["description"])
        self.assertEqual(finding["description"].count("Reference checks ("), 1)
        self.assertEqual(finding["source_checks"][-1].split(":")[0], SECOND)

    def test_only_exact_generated_footer_is_replaced(self):
        finding = {
            "vuln_name": FIRST,
            "description": "Operator text before source checks",
            "evidence": "443/tcp open HTTPS",
            "confidence": "possible",
        }
        verify([finding])
        finding["description"] += "\nOperator comment added after review"
        verify([finding])
        self.assertIn("Operator comment added after review", finding["description"])
        # Refuse to strip arbitrary user comments along with generated data.
        self.assertGreaterEqual(finding["description"].count("Reference checks ("), 2)

    def test_client_lookup_still_injected_on_repeated_calls(self):
        finding = {
            "vuln_name": FIRST,
            "description": "Operator note",
            "evidence": "443/tcp open HTTPS",
        }
        nvd = Mock(return_value="listed")
        for _ in range(2):
            verify_findings(
                [finding], "443/tcp open HTTPS",
                nvd_lookup=nvd,
                applicability_lookup=lambda *_args, **_kw: "unknown",
                kev_loader=lambda: {FIRST},
            )
        self.assertEqual(nvd.call_count, 2)
        self.assertEqual(finding["description"].count("Reference checks ("), 1)


if __name__ == "__main__":
    unittest.main()
