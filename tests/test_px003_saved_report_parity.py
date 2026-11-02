"""PX-003: saved-session HTML/PDF and JSON/SARIF evidence/coverage parity.

Only synthetic stored assessments are rendered. No network, scanners, database
or model are contacted; a mocked PDF builder captures the real flowables.
"""
from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from reportlab.platypus import Paragraph, Table

from penx_app.domain.scan_models import ScanResult, ScannerResult
from penx_app.reporting.export import export_html, export_pdf
from penx_app.reporting.machine_reports import report_payload, sarif_payload
from penx_app.reporting.report_design import _report, _summary
from penx_app.reporting.scan_coverage import COVERAGE_EXPLANATION


SCAN = (
    "[ NMAP OUTPUT ]\n"
    + "=" * 40 + "\n"
    + "[PENX ADAPTER STATUS: COMPLETE; EVIDENCE: YES]\n"
    + "443/tcp open https fixture-service\n"
    + "[ NIKTO OUTPUT ]\n"
    + "=" * 40 + "\n"
    + "[PENX ADAPTER STATUS: PARTIAL; EVIDENCE: NO]\n"
    + "[!] Timed out; no findings established\n"
    + "[ DNS OUTPUT ]\n"
    + "=" * 40 + "\n"
    + "[PENX ADAPTER STATUS: COMPLETE; EVIDENCE: NO]\n"
    + "No registration records found\n"
)


def saved_fixture():
    sl = 321
    return {
        "history": (sl, "example.test", "2026-11-02 10:00", "active"),
        "summary": (1, sl, SCAN, "UNVERIFIED MODEL TRANSCRIPT ONLY",
                    "MEDIUM", "fixture-local", "2026-11-02 10:05"),
        "scan_result": ScanResult((
            ScannerResult("nmap", "443/tcp open https fixture-service",
                          "COMPLETE", True, "Nmap"),
            ScannerResult("nikto", "[!] Timed out", "PARTIAL", False, "Nikto"),
            ScannerResult("dns", "No registration records found",
                          "COMPLETE", False, "DNS"),
        )),
        "vulns": [
            (1, sl, "Validated scanner quote", "low", "confirmed", "443",
             "https", "Synthetic observation.\nEvidence: 443/tcp open https fixture-service"),
            (2, sl, "Unverified severity hypothesis", "high", "confirmed", "8443",
             "https", "AI text without any matching scanner quote"),
            (3, sl, "Rejected hallucination", "critical", "confirmed", "22",
             "ssh", "Unsupported model fabrication"),
            (4, sl, "Review DNS settings", "info", "recommendation", "",
             "dns", "No automated verification."),
        ],
        "fixes": [(1, sl, 1, "Review the synthetic configuration", "fixture"),
                  (2, sl, 3, "Rejected mitigation", "fixture")],
        "corrections": [(11, sl, 3, "hallucination", "", "",
                         "No observed scanner evidence", "2026-11-02")],
        "exploits": [],
    }


def pdf_texts(data, path):
    """Read original PDF layout flowables instead of OCR or screenshots."""
    with patch("penx_app.reporting.terminal_pdf.SimpleDocTemplate") as template:
        export_pdf(data, path)
    build = template.return_value.build
    build.assert_called_once()
    elements = build.call_args.args[0]
    texts = []
    def record(item):
        if isinstance(item, Paragraph):
            texts.append(item.text)
        elif isinstance(item, Table):
            for row in item._cellvalues:
                for cell in row:
                    record(cell)
        elif hasattr(item, "_content"):
            for part in item._content:
                record(part)
    for item in elements:
        record(item)
    return "\n".join(texts)


class SavedAssessmentPresentationParityTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(prefix="penx-report-parity-")
        self.addCleanup(self.folder.cleanup)

    def test_completed_adapter_without_evidence_is_not_claimed_as_observation(self):
        data = saved_fixture()
        parsed = _report(data)
        self.assertEqual(parsed["coverage"]["status"], "PARTIAL")
        self.assertEqual(parsed["coverage"]["failed"], ["NIKTO"])
        self.assertIn("DNS", parsed["coverage"]["completed"])
        self.assertFalse(data["scan_result"].results[2].evidence)
        html = Path(export_html(data, self.folder.name)).read_text(encoding="utf-8")
        pdf = pdf_texts(data, self.folder.name)
        self.assertIn("DNS</span><strong>COLLECTED</strong>", html)
        self.assertIn("DNS: COLLECTED", pdf)
        self.assertIn(COVERAGE_EXPLANATION, html)
        self.assertIn(COVERAGE_EXPLANATION, pdf)
        self.assertIn("does not assert usable evidence", COVERAGE_EXPLANATION)
        self.assertNotIn("COLLECTED means scanner evidence exists", pdf)

    def test_filtered_findings_confidence_and_coverage_agree_across_formats(self):
        data = saved_fixture()
        machine = report_payload(data)
        sarif = sarif_payload(data)["runs"][0]["results"]
        # Saved JSON retains advisory recommendations as an explicit
        # recommendation entry; SARIF excludes them from security alerts.
        self.assertEqual([r["name"] for r in machine["findings"]],
                         ["Validated scanner quote", "Unverified severity hypothesis",
                          "Review DNS settings"])
        self.assertEqual([r["confidence"] for r in machine["findings"]],
                         ["confirmed", "possible", "recommendation"])
        self.assertEqual([r["properties"]["confidence"] for r in sarif],
                         ["confirmed", "possible"])
        self.assertTrue(machine["findings"][0]["evidence_ref"])
        self.assertIsNone(machine["findings"][1]["evidence_ref"])
        self.assertEqual(len(sarif), 2)
        parsed = _report(data)
        self.assertIn("1 confirmed, 1 potential", _summary(parsed))
        html = Path(export_html(data, self.folder.name)).read_text(encoding="utf-8")
        pdf = pdf_texts(data, self.folder.name)
        for name in ("Validated scanner quote", "Unverified severity hypothesis"):
            self.assertIn(name, html)
            self.assertIn(name, pdf)
        for forbidden in ("Rejected hallucination", "Rejected mitigation"):
            self.assertNotIn(forbidden, html)
            self.assertNotIn(forbidden, pdf)
        self.assertIn("Status: Confirmed", html)
        self.assertIn("Status: Potential", html)
        self.assertIn("Status: Confirmed", pdf)
        self.assertIn("Status: Potential", pdf)
        self.assertIn("NIKTO", html)
        self.assertIn("NIKTO: INCOMPLETE", pdf)
        ref = machine["findings"][0]["evidence_ref"]
        self.assertIn(ref, html)
        self.assertIn(ref, pdf)
        self.assertNotIn("UNVERIFIED MODEL TRANSCRIPT ONLY", pdf)

    def test_real_pdf_builds_after_cross_format_validation(self):
        path = Path(export_pdf(saved_fixture(), self.folder.name))
        self.assertTrue(path.read_bytes().startswith(b"%PDF-"))
        self.assertGreater(path.stat().st_size, 2000)


if __name__ == "__main__":
    unittest.main()
