"""Offline regressions for issue #68 JSON/SARIF and redaction exports."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from penx_app.reporting.machine_reports import report_payload, sarif_payload, write_machine_report, export_cli


class MachineReportTests(unittest.TestCase):
    def setUp(self):
        quote = "443/tcp open  https Apache httpd 2.4.58"
        self.data = {
            "history": (32, "example.test", "2026-10-15 12:00:00", "active"),
            "summary": (1, 32, "[ NMAP OUTPUT ]\n" + quote,
                        "AI might be incorrect", "MEDIUM", "local", "2026-10-15"),
            "vulns": [
                (51, 32, "Observed service 192.0.2.5", "medium", "confirmed",
                 "443", "https", "Supported detail\nEvidence: " + quote),
                (52, 32, "Invented RCE", "critical", "confirmed",
                 "443", "https", "No verified quote"),
                (53, 32, "Rejected old issue", "high", "likely",
                 "80", "http", "Invalid finding"),
                (54, 32, "Security recommendation", "info", "recommendation",
                 "", "", "Informational note"),
            ],
            "corrections": [(1, 32, 53, "hallucination", "old", "new", "not substantiated", "2026-10-15")],
            "fixes": [],
        }

    def test_json_downgrades_unverified_and_excludes_hallucinations(self):
        result = report_payload(self.data)
        self.assertEqual(result["session"], 32)
        self.assertEqual([v["id"] for v in result["findings"]], [51, 52, 54])
        self.assertEqual(result["findings"][0]["status"], "scanner-quote-matched")
        self.assertEqual(result["findings"][0]["evidence_ref"], "scan:32:finding:51")
        self.assertEqual(result["findings"][1]["status"], "review-required")
        self.assertEqual(result["findings"][1]["confidence"], "possible")
        self.assertEqual(result["findings"][1]["evidence"], "")
        self.assertNotIn("raw_scan", result)

    def test_redaction_masks_target_and_valid_ipv4(self):
        redacted = report_payload(self.data, redact=True)
        as_text = json.dumps(redacted)
        self.assertNotIn("example.test", as_text)
        self.assertNotIn("192.0.2.5", as_text)
        self.assertIn("[TARGET REDACTED]", as_text)
        self.assertIn("[IPv4 REDACTED]", as_text)
        self.assertEqual(redacted["findings"][0]["status"], "scanner-quote-matched")

    def test_sarif_is_valid_envelope_and_omits_recommendations(self):
        report = sarif_payload(self.data, redact=True)
        self.assertEqual(report["version"], "2.1.0")
        run = report["runs"][0]
        self.assertEqual(len(run["results"]), 2)
        self.assertEqual(len(run["tool"]["driver"]["rules"]), 2)
        self.assertEqual(run["results"][0]["level"], "warning")
        self.assertEqual(run["results"][1]["level"], "error")
        self.assertEqual(run["results"][1]["properties"]["evidenceStatus"], "review-required")

    def test_export_never_overwrites_existing_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = write_machine_report(self.data, tmp, fmt="json")
            first.write_text("existing file cannot be overwritten", encoding="utf-8")
            second = write_machine_report(self.data, tmp, fmt="json")
            self.assertNotEqual(first, second)
            self.assertEqual(first.read_text(encoding="utf-8"), "existing file cannot be overwritten")
            self.assertEqual(json.loads(second.read_text(encoding="utf-8"))["session"], 32)
            self.assertFalse(list(Path(tmp).glob(".penx-report-*")))

    def test_invalid_format_and_missing_session_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                write_machine_report(self.data, tmp, fmt="xml")
        with self.assertRaises(ValueError):
            report_payload({"history": None, "summary": None})

    def test_headless_cli_exports_without_invoking_scanners(self):
        with tempfile.TemporaryDirectory() as tmp, \
             patch("penx_app.reporting.export.fetch_session", return_value=self.data) as fetch, \
             patch("penx_app.scanners.tools.run_default_recon", side_effect=AssertionError("must not scan")):
            status = export_cli(["32", "--format", "sarif", "--redact", "--output-dir", tmp])
            self.assertEqual(status, 0)
            fetch.assert_called_once_with(32)
            reports = list(Path(tmp).glob("*.sarif"))
            self.assertEqual(len(reports), 1)
            text = reports[0].read_text(encoding="utf-8")
            self.assertNotIn("example.test", text)
            self.assertNotIn("192.0.2.5", text)

    def test_html_pdf_show_exact_quote_and_stable_reference(self):
        from penx_app.reporting.export import export_html, export_pdf
        with tempfile.TemporaryDirectory() as tmp:
            html_file = export_html(self.data, tmp)
            body = Path(html_file).read_text(encoding="utf-8")
            self.assertIn("scan:32:finding:51", body)
            self.assertIn("No exact quoted scanner evidence verified", body)
            self.assertIn("443/tcp open", body)
            self.assertNotIn("Evidence reference: scan:32:finding:52", body)
            pdf_file = export_pdf(self.data, tmp)
            self.assertTrue(Path(pdf_file).is_file())
            self.assertGreater(Path(pdf_file).stat().st_size, 700)

    def test_missing_session_nonzero(self):
        with patch("penx_app.reporting.export.fetch_session", return_value={"history": None}):
            self.assertEqual(export_cli(["999", "--format", "json"]), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
