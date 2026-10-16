"""Long report fixture exercises renderers without real targets or customer data."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from penx_app.reporting.export import export_html, export_pdf
from penx_app.reporting.machine_reports import report_payload, sarif_payload
from penx_app.reporting.report_view import ReportView


class LargeSyntheticReportTests(unittest.TestCase):
    def fixture(self):
        sl = 208
        findings = []
        corrections = []
        fixes = []
        for i in range(1, 121):
            name = f"FixtureObservation-{i:03d}"
            findings.append((
                i, sl, name, "medium" if i % 5 else "info",
                "recommendation" if i % 5 == 0 else "possible",
                str(1000 + i), "http",
                "Synthetic offline source. " + ("A validated fixture. " * 12),
            ))
            fixes.append((2000 + i, sl, i, f"Verify fixture configuration {i}", "fixture"))
            if i % 11 == 0:
                corrections.append((
                    3000 + i, sl, i, "hallucination", "", "",
                    "Offline fixture rejection", "now",
                ))
        return {
            "history": (sl, "fixture.invalid", "2026-10-16", "active"),
            "summary": (1, sl, "Synthetic offline scan", "No real assessment",
                        "UNKNOWN", "local-fixture", "2026-10-16"),
            "vulns": findings,
            "corrections": corrections,
            "fixes": fixes,
            "exploits": [],
        }

    def test_large_cross_format_export_does_not_reintroduce_rejected_items(self):
        original = self.fixture()
        baseline = tuple(original["vulns"])
        view = ReportView.from_session(original)
        expected_ids = [row[0] for row in view.active_findings]
        rejected_ids = {row[2] for row in original["corrections"]}
        self.assertEqual(len(expected_ids), 120 - len(rejected_ids))

        data = report_payload(original)
        sarif = sarif_payload(original)
        self.assertEqual([item["id"] for item in data["findings"]], expected_ids)
        self.assertTrue(set(
            result["properties"]["penxFindingId"]
            for result in sarif["runs"][0]["results"]
        ).issubset(expected_ids))

        with tempfile.TemporaryDirectory(prefix="penx-long-report-") as folder:
            html = Path(export_html(original, folder)).read_text(encoding="utf-8")
            pdf_path = Path(export_pdf(original, folder))
            self.assertGreater(pdf_path.stat().st_size, 3000)
            self.assertTrue(pdf_path.read_bytes().startswith(b"%PDF"))
            for i in (1, 33, 77, 120):
                name = f"FixtureObservation-{i:03d}"
                if i in rejected_ids:
                    self.assertNotIn(name, html)
                else:
                    self.assertIn(name, html)
            for i in rejected_ids:
                self.assertNotIn(f"FixtureObservation-{i:03d}", html)

            # Machine output remains serializable and self-consistent.
            self.assertEqual(
                len(json.loads(json.dumps(data))["findings"]), len(expected_ids)
            )
        self.assertEqual(tuple(original["vulns"]), baseline)


if __name__ == "__main__":
    unittest.main(verbosity=2)
