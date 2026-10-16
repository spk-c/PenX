"""Reviewed finding selection is consistent across HTML/PDF and JSON/SARIF."""
import unittest

from penx_app.reporting.export import _active_report_data
from penx_app.reporting.report_view import ReportView
from penx_app.reporting.machine_reports import report_payload, sarif_payload


class ReportViewContracts(unittest.TestCase):
    def fixture(self):
        first = (1, 7, "Confirmed candidate", "high", "possible", "443", "https", "Evidence: 443/tcp open")
        rejected = (2, 7, "Rejected candidate", "medium", "possible", "80", "http", "Unsupported")
        recovered = (3, 7, "Verified again", "low", "possible", "22", "ssh", "Evidence: 22/tcp open")
        return {
            "history": (7, "example.test", "2026-10-15", "active"),
            "summary": (1, 7, "443/tcp open\n22/tcp open", "Analysis", "HIGH", "local", "2026-10-15"),
            "vulns": [first, rejected, recovered],
            "fixes": [(11, 7, 1, "Update TLS", "ai"), (12, 7, 2, "Remove false positive", "ai"),
                      (13, 7, 3, "Verify SSH", "ai")],
            "corrections": [(21, 7, 2, "hallucination"), (22, 7, 3, "hallucination"),
                            (23, 7, 3, "verified")],
        }

    def test_projection_preserves_original_and_filters_linked_fixes(self):
        source = self.fixture()
        original_findings = list(source["vulns"])
        view = ReportView.from_session(source)
        self.assertEqual([v[0] for v in view.active_findings], [1, 3])
        self.assertEqual([fix[2] for fix in view.active_fixes], [1, 3])
        self.assertEqual([v[0] for v in _active_report_data(source)["vulns"]], [1, 3])
        self.assertEqual(source["vulns"], original_findings)
        self.assertEqual(len(source["corrections"]), 3)

    def test_json_and_sarif_use_the_same_review_policy(self):
        source = self.fixture()
        machine = report_payload(source)
        self.assertEqual([finding["id"] for finding in machine["findings"]], [1, 3])
        sarif = sarif_payload(source)
        self.assertEqual([item["properties"]["penxFindingId"]
                          for item in sarif["runs"][0]["results"]], [1, 3])


if __name__ == "__main__":
    unittest.main()
