"""Cross-format saved-session review parity without scanner/model/network I/O."""
import json
from pathlib import Path
import tempfile
import unittest

from penx_app.reporting.export import export_html, export_pdf
from penx_app.reporting.machine_reports import report_payload, sarif_payload, write_machine_report
from penx_app.reporting.report_view import ReportView


class CrossFormatParityTests(unittest.TestCase):
    def setUp(self):
        self.quote = "443/tcp open https fixture-service"
        self.data = {
            "history": (71, "fixture.example.test", "2026-10-15", "active"),
            "summary": (1, 71, "[ NMAP OUTPUT ]\n" + self.quote,
                        "Original untrusted model output", "MEDIUM", "fixture", "2026-10-15"),
            "vulns": [
                (1, 71, "ActiveAlpha", "medium", "possible", "443", "https",
                 "Evidence: " + self.quote),
                (2, 71, "RejectedGamma", "high", "possible", "80", "http",
                 "Rejected model hypothesis"),
                (3, 71, "RestoredBeta", "low", "possible", "22", "ssh",
                 "Unverified saved observation"),
                (4, 71, "ReviewerAction", "info", "recommendation", "", "",
                 "Inspect the configuration"),
            ],
            "corrections": [
                (11, 71, 2, "hallucination", "", "", "No evidence", "now"),
                (12, 71, 3, "hallucination", "", "", "Earlier rejection", "now"),
                (13, 71, 3, "verified", "", "", "Human reverified", "now"),
            ],
            "fixes": [(21, 71, 1, "Review exposure", "fixture"),
                      (22, 71, 2, "Rejected fix", "fixture"),
                      (23, 71, 3, "Verify again", "fixture")],
        }

    def test_html_pdf_json_sarif_share_reviewed_active_findings(self):
        view = ReportView.from_session(self.data)
        self.assertEqual([r[0] for r in view.active_findings], [1, 3, 4])
        self.assertEqual([r[2] for r in view.active_fixes], [1, 3])
        self.assertEqual(len(self.data["vulns"]), 4)
        json_data = report_payload(self.data)
        sarif_data = sarif_payload(self.data)
        self.assertEqual([r["id"] for r in json_data["findings"]], [1, 3, 4])
        self.assertEqual(
            [r["properties"]["penxFindingId"] for r in sarif_data["runs"][0]["results"]],
            [1, 3],
        )
        with tempfile.TemporaryDirectory() as folder:
            html_path = Path(export_html(self.data, folder))
            pdf_path = Path(export_pdf(self.data, folder))
            html = html_path.read_text(encoding="utf-8")
            self.assertIn("ActiveAlpha", html)
            self.assertIn("RestoredBeta", html)
            self.assertIn("ReviewerAction", html)
            self.assertNotIn("RejectedGamma", html)
            self.assertNotIn("Rejected fix", html)
            self.assertTrue(pdf_path.read_bytes().startswith(b"%PDF"))
            self.assertGreater(pdf_path.stat().st_size, 750)
            json_path = write_machine_report(self.data, folder, fmt="json")
            sarif_path = write_machine_report(self.data, folder, fmt="sarif")
            self.assertEqual([r["id"] for r in json.loads(json_path.read_text())["findings"]],
                             [1, 3, 4])
            self.assertEqual(len(json.loads(sarif_path.read_text())["runs"][0]["results"]), 2)

    def test_no_mutation_and_legacy_evidence_never_becomes_verified_by_text_alone(self):
        originals = list(self.data["vulns"])
        first = report_payload(self.data)
        second = report_payload(self.data)
        self.assertEqual(first, second)
        self.assertEqual(originals, self.data["vulns"])
        self.assertEqual(first["findings"][1]["status"], "review-required")
        self.assertEqual(first["findings"][1]["confidence"], "possible")
        self.assertEqual(first["findings"][1]["evidence"], "")


if __name__ == "__main__":
    unittest.main()
