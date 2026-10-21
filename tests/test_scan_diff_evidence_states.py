"""Offline tests: disappearance is never automatic remediation."""
import unittest

from penx_app.application.scan_trends import compare_sessions, report_text
from penx_app.domain.scan_models import ScanResult, ScannerResult


def session(number, *, finding=True, scanner_status="COMPLETE", selected=True,
            evidence=True, raw_override=None):
    raw = (
        "[ NMAP OUTPUT ]\n"
        "[PENX ADAPTER STATUS: COMPLETE; EVIDENCE: YES]\n"
        "Nmap 7.94 scan initiated\n"
        "80/tcp open http\n"
        "Nmap done: 1 IP address scanned\n"
    ) if raw_override is None else raw_override
    scan_result = None
    if selected:
        scan_result = ScanResult((
            ScannerResult("nmap", "", scanner_status,
                          scanner_status == "COMPLETE", "Nmap"),
        ))
    rows = []
    if finding:
        description = ("An HTTP service was found.\n"
                       "Evidence: Nmap output: \"80/tcp open http\"") if evidence else "No evidence"
        rows = [(10, number, "Open HTTP service", "low", "possible",
                 "80", "http", description)]
    return {"history": (number, "example.test", "2026-10-21", "active"),
            "summary": (1, number, raw, "Model assessment", "LOW"),
            "vulns": rows, "corrections": [], "scan_result": scan_result}


CLEAN_NMAP = (
    "[ NMAP OUTPUT ]\n"
    "[PENX ADAPTER STATUS: COMPLETE; EVIDENCE: YES]\n"
    "Nmap 7.94 scan initiated\n"
    "Nmap done: 1 IP address scanned\n"
)


class ScanDiffEvidenceStatesTests(unittest.TestCase):
    def test_complete_followup_is_not_observed_never_resolved(self):
        old = session(1)
        new = session(2, finding=False, raw_override=CLEAN_NMAP)
        diff = compare_sessions(old, new)
        self.assertEqual(diff["finding_state_counts"]["not_observed"], 1)
        self.assertEqual(diff["finding_state_counts"]["resolved"], 0)
        self.assertEqual(diff["resolved_findings"], [])
        self.assertIn("[NOT OBSERVED]", report_text(diff))
        trace = diff["finding_states"][0]["finding"]["source"]
        self.assertEqual(trace["scanner"], "NMAP")
        self.assertEqual(trace["scanner_version"], "7.94")
        self.assertEqual(trace["evidence_ref"], "scan:1:finding:10")
        self.assertIn("80/tcp open http", trace["evidence"])
        self.assertEqual(trace["raw_evidence"], "80/tcp open http")
        self.assertIn("Original scanner excerpt", report_text(diff))

    def test_model_omission_with_repeated_evidence_is_still_present(self):
        diff = compare_sessions(session(1), session(2, finding=False))
        self.assertEqual(diff["finding_state_counts"]["still_present"], 1)
        self.assertEqual(diff["finding_state_counts"]["not_observed"], 0)
        self.assertIn("reproduced the original", report_text(diff))

    def test_missing_scanner_is_not_checked(self):
        diff = compare_sessions(session(1), session(2, finding=False, selected=False))
        self.assertEqual(diff["finding_state_counts"]["not_checked"], 1)
        self.assertIn("[NOT CHECKED]", report_text(diff))

    def test_failed_or_partial_scanner_does_not_look_fixed(self):
        for status in ("FAILED", "PARTIAL"):
            with self.subTest(status=status):
                diff = compare_sessions(
                    session(1), session(2, finding=False, scanner_status=status))
                self.assertEqual(diff["finding_state_counts"]["scan_failed"], 1)
                self.assertEqual(diff["finding_state_counts"]["not_observed"], 0)
                self.assertEqual(diff["finding_state_counts"]["resolved"], 0)

    def test_nmap_metadata_failure_overrules_text_footer(self):
        prior = session(1)
        later = session(2, finding=False, scanner_status="FAILED",
                        raw_override=CLEAN_NMAP)
        result = compare_sessions(prior, later)
        self.assertFalse(result["port_comparison_reliable"])
        self.assertEqual(result["missing_ports"], {})
        self.assertEqual(result["finding_state_counts"]["scan_failed"], 1)

    def test_legacy_coverage_fails_closed(self):
        old = session(1)
        new = session(2, finding=False)
        new.pop("scan_result")
        diff = compare_sessions(old, new)
        self.assertEqual(diff["finding_state_counts"]["not_checked"], 1)

    def test_finding_without_attributed_evidence_is_not_checked(self):
        old = session(1, evidence=False)
        new = session(2, finding=False)
        diff = compare_sessions(old, new)
        self.assertEqual(diff["finding_state_counts"]["not_checked"], 1)
        self.assertEqual(diff["finding_states"][0]["finding"]["source"]["scanner"], None)

    def test_scanner_version_never_invented(self):
        raw = ("[ NMAP OUTPUT ]\n"
               "[PENX ADAPTER STATUS: COMPLETE; EVIDENCE: YES]\n"
               "80/tcp open http\nNmap done: 1 IP address scanned\n")
        old = session(1, raw_override=raw)
        diff = compare_sessions(old, session(2, finding=False))
        trace = diff["finding_states"][0]["finding"]["source"]
        self.assertIsNone(trace["scanner_version"])
        self.assertIn("Version: not recorded", report_text(diff))

    def test_current_finding_preserved_with_provenance(self):
        diff = compare_sessions(session(1), session(2))
        self.assertEqual(diff["finding_state_counts"]["still_present"], 1)
        self.assertEqual(diff["finding_state_counts"]["not_observed"], 0)
        self.assertEqual(diff["finding_state_counts"]["scan_failed"], 0)


if __name__ == "__main__":
    unittest.main()
