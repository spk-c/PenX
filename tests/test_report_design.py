"""Visual-report regression checks: legibility, semantics and untrusted input."""
from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from penx_app.reporting.export import export_html, export_pdf


def sample():
    # Exact DB tuple columns used by the existing exporter. One recommendation
    # must NOT inflate the number of saved security findings.
    text = (
        "Observed a proxy at 443/tcp; this is an informational fingerprint "
        "rather than a confirmed origin vulnerability. "
        + "A long service description should wrap within the available width. " * 9
    )
    text += "\nEvidence: nmap text contains confirmed WordPress version disclosure scanner evidence"
    return {
        "history": (5, "shop.example.test", "2026-10-14 23:25:23", "active"),
        "summary": (5, 5, "nmap text contains confirmed WordPress version disclosure scanner evidence",
                    "Historical AI analysis: <script>alert('x')</script>\n"
                    + "Very long raw input with URLs and quotes: " + "Q" * 190,
                    "LOW", "test-model", "2026-10-14 23:34:43"),
        "vulns": [
            (21, 5, "WordPress version disclosure", "info", "confirmed", "443",
             "WordPress / Elementor / edge proxy", text),
            (22, 5, "Verify WordPress stack", "info", "recommendation", "",
             "", "Check the installed versions before claiming exploitation."),
        ],
        "fixes": [(11, 5, 21, "Review available vendor patches", "ai")],
        "exploits": [],
        "corrections": [(9, 5, 21, "verified",
                         '<img src=x onerror="alert(1)">', "informational only",
                         "The previous wording was unsupported.")],
    }


class BrandedReportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

    def test_html_brand_and_semantic_groups(self):
        path = Path(export_html(sample(), self.temp.name))
        html = path.read_text(encoding="utf-8")
        self.assertIn("PenX | Security Assessment", html)
        self.assertIn("LOCAL AI / SECURITY RECON", html)
        self.assertIn('class="brandname" aria-label="PenX">PEN', html)
        self.assertIn("color:var(--magenta)", html)
        self.assertIn("color:var(--green)", html)
        self.assertIn("RISK: LOW", html)
        self.assertIn("Scanned IP / edge", html)
        self.assertIn("Origin webserver", html)
        self.assertIn("Status: Confirmed", html)
        self.assertIn('[01]', html)
        self.assertIn('[F-01]', html)
        self.assertIn('[R-01]', html)
        self.assertIn('[C-01]', html)
        self.assertIn('class="findings-grid"', html)
        self.assertIn('class="metric metric-info"', html)
        self.assertIn('class="finding severity-info status-confirmed"', html)
        self.assertIn('class="record review"', html)
        self.assertIn("test-model", html)
        self.assertIn('id="findings"', html)
        self.assertIn('id="recommendations"', html)
        self.assertIn("1 confirmed, 0 potential finding(s), 1 recommendation(s)", html)
        self.assertIn("WordPress version disclosure", html)
        self.assertIn("Verify WordPress stack", html)
        self.assertIn("METATRON", html)
        self.assertIn("@media print", html)
        self.assertIn("<details>", html)
        self.assertNotIn("<script>alert('x')</script>", html)
        self.assertIn("&lt;script&gt;alert(&#x27;x&#x27;)&lt;/script&gt;", html)
        self.assertNotIn('<img src=x onerror="alert(1)">', html)
        self.assertIn("&lt;img src=x", html)

    def test_pdf_holds_long_service_and_unverified_ai(self):
        path = Path(export_pdf(sample(), self.temp.name))
        contents = path.read_bytes()
        self.assertTrue(contents.startswith(b"%PDF-"))
        self.assertGreater(len(contents), 2200)

    def test_long_description_can_flow_across_pdf_pages(self):
        report = sample()
        long_observation = "Authorized analysis detail with a long explanation. " * 1500
        first = list(report["vulns"][0])
        first[7] = long_observation
        report["vulns"][0] = tuple(first)
        pdf = Path(export_pdf(report, self.temp.name))
        self.assertTrue(pdf.read_bytes().startswith(b"%PDF-"))
        self.assertGreater(pdf.stat().st_size, 3500)

    def test_clean_empty_export(self):
        report = sample()
        report["vulns"] = []
        report["fixes"] = []
        report["corrections"] = []
        self.assertIn("No active findings recorded",
                      Path(export_html(report, self.temp.name)).read_text(encoding="utf-8"))
        self.assertTrue(Path(export_pdf(report, self.temp.name)).is_file())

    def test_report_does_not_inject_untrusted_target(self):
        report = sample()
        report["history"] = (7, '<img src=x onerror=alert(1)>', "2026-10-14", "active")
        html = Path(export_html(report, self.temp.name)).read_text(encoding="utf-8")
        self.assertIn("&lt;img src=x onerror=alert(1)&gt;", html)
        self.assertNotIn('<img src=x onerror=alert(1)>', html)
        self.assertNotIn("javascript:", html)
        pdf = Path(export_pdf(report, self.temp.name))
        self.assertTrue(pdf.exists())

class SL13PdfAndLegacyAuditTests(unittest.TestCase):
    def test_pdf_repair_of_real_mojibake_sequence(self):
        from penx_app.reporting.terminal_pdf import _pdf_ai_appendix_text
        self.assertEqual(
            _pdf_ai_appendix_text("Analysis â\x80\x94 evidence â\x86\x92 action"),
            "Analysis -- evidence -> action"
        )

    def test_sl13_archived_cve_and_unexecuted_exploit_are_labeled(self):
        report = sample()
        report["summary"] = (
            5, 5, "22/tcp open ssh OpenSSH 7.4",
            "Unverified old analysis", "MEDIUM", "test", "2026-10-15"
        )
        report["vulns"] = [(
            81, 5, "OpenSSH 7.4 CVE candidate", "high", "possible", "22", "ssh",
            "OpenSSH 7.4 may have CVE-2024-6387 and CVE-2023-38408."
        )]
        report["exploits"] = [(
            91, 5, "MySQL credential brute force", "hydra",
            "NOT RUN", "Potential only; credentials were not tested",
            "No exploitation was performed."
        )]
        with tempfile.TemporaryDirectory() as folder:
            html = Path(export_html(report, folder)).read_text(encoding="utf-8")
            pdf = Path(export_pdf(report, folder))
            self.assertTrue(pdf.exists())
        self.assertIn("HISTORICAL SSH CVE WARNING", html)
        self.assertIn("NOT EXECUTED", html)
        self.assertIn("Legacy model suggestion", html)

    def test_counts_use_verifiable_quotes_like_pdf_and_sarif(self):
        from penx_app.reporting.report_design import _report, _counts, _summary
        report = sample()
        first = list(report["vulns"][0])
        first[7] = "Reported without any literal scanner citation."
        report["vulns"][0] = tuple(first)
        parsed = _report(report)
        self.assertEqual(_counts(parsed)["info"], 0)
        self.assertIn("0 confirmed, 1 potential", _summary(parsed))


class HostIntelligenceTests(unittest.TestCase):
    def test_edge_ip_not_origin(self):
        from penx_app.reporting.report_design import _scan_intelligence
        evidence = ("Nmap scan report for example.test (188.114.96.12)\n"
                    "80/tcp open http Cloudflare http proxy\nServer: cloudflare")
        result = _scan_intelligence(evidence)
        self.assertEqual(result["addresses"], ["188.114.96.12"])
        self.assertEqual(result["proxy"], "Cloudflare")
        self.assertEqual(result["webserver"], "Origin not identified")

    def test_scanner_failures_flagged(self):
        from penx_app.reporting.report_design import _scan_intelligence
        result = _scan_intelligence("Nikto: ERROR: Required module not found: XML::Writer")
        self.assertIn("Nikto", result["failed"])
        self.assertEqual(result["addresses"], [])

    def test_possible_finding_not_confirmed(self):
        from penx_app.reporting.report_design import _counts, _finding_status
        report = {"findings": [(3, 1, "possible auth bypass", "low", "possible", "443", "HTTP", "test")]}
        self.assertEqual(_finding_status(report["findings"][0]), "Potential")
        self.assertEqual(_counts(report)["low"], 0)



class ReportModesTests(unittest.TestCase):
    def test_executive_exports_exclude_unverified_appendix(self):
        data = sample()
        with tempfile.TemporaryDirectory() as folder:
            html_path = Path(export_html(data, folder, mode="executive"))
            pdf_path = Path(export_pdf(data, folder, mode="executive"))
            content = html_path.read_text(encoding="utf-8")
            self.assertIn("host-grid", content)
            self.assertNotIn('id="appendix"', content)
            self.assertNotIn('id="activity"', content)
            self.assertIn("Saved scan evidence", content)
            self.assertTrue(pdf_path.read_bytes().startswith(b"%PDF-"))
            self.assertIn("executive", pdf_path.name)

    def test_technical_keeps_audit_sections(self):
        with tempfile.TemporaryDirectory() as folder:
            html = Path(export_html(sample(), folder)).read_text(encoding="utf-8")
            self.assertIn('id="appendix"', html)
            self.assertIn('id="review"', html)

    def test_invalid_export_mode_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(ValueError):
                export_html(sample(), folder, mode="not-a-mode")





class SavedRecommendationPresentationTests(unittest.TestCase):
    def test_legacy_flyingpress_duplicates_are_consolidated(self):
        from penx_app.reporting.report_design import _display_recommendations
        first = (43, 7, "FlyingPress theme version unconfirmed", "info",
                 "recommendation", "", "", "FlyingPress theme version not shown.")
        second = (46, 7, "Confirm FlyingPress theme version", "info",
                  "recommendation", "", "", "Check FlyingPress theme version.")
        result = _display_recommendations([first, second])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0][2], "Confirm FlyingPress plugin version")
        self.assertEqual(first[2], "FlyingPress theme version unconfirmed")




class ConsistentCoverageTests(unittest.TestCase):
    def test_saved_adapter_failure_controls_all_report_coverage_labels(self):
        report = sample()
        summary = list(report["summary"])
        summary[2] = "[ NIKTO OUTPUT ]\n- ERROR: The -port option cannot be used with a full URI\n[SCAN COVERAGE]\nNIKTO FAILED"
        report["summary"] = tuple(summary)
        with tempfile.TemporaryDirectory() as folder:
            html = Path(export_html(report, folder)).read_text(encoding="utf-8")
            self.assertIn("PARTIAL", html)
            self.assertNotIn("No recorded failures", html)
            pdf = Path(export_pdf(report, folder))
            self.assertTrue(pdf.exists())



class SL11PresentationRegressions(unittest.TestCase):
    def test_html_navigation_matches_sections_without_or_with_comparison(self):
        from penx_app.reporting.report_design import export_html
        with tempfile.TemporaryDirectory() as folder:
            html = Path(export_html(sample(), folder)).read_text(encoding="utf-8")
        for index, _heading, link in (
            ("04", "Historical AI exploit proposals", "AI proposals"),
            ("05", "Corrections", "Review"),
            ("06", "Original AI output", "AI appendix"),
        ):
            self.assertIn(f'<span class="section-no">[{index}]</span>', html)
            self.assertIn(f"{index} / {link}</a>", html)
        self.assertIn("Confirmed findings by severity", html)

    def test_html_shows_real_failed_scanner_names_instead_of_partial_pseudo_tool(self):
        data = sample()
        summary = list(data["summary"])
        summary[2] = (
            "[ NMAP OUTPUT ]\n" + "=" * 50 + "\n"
            "[PENX ADAPTER STATUS: COMPLETE; EVIDENCE: YES]\n443/tcp open https\n"
            "[ NIKTO (OPTIONAL) OUTPUT ]\n" + "=" * 50 + "\n"
            "[PENX ADAPTER STATUS: PARTIAL; EVIDENCE: NO]\n"
            "[!] Timed out after 300s\n[PARTIAL OUTPUT]\n"
            "[ NUCLEI (EXPLICIT OPT-IN) OUTPUT ]\n" + "=" * 50 + "\n"
            "[PENX ADAPTER STATUS: PARTIAL; EVIDENCE: NO]\n"
            "[!] Timed out after 240s\n"
        )
        data["summary"] = tuple(summary)
        with tempfile.TemporaryDirectory() as folder:
            html = Path(export_html(data, folder)).read_text(encoding="utf-8")
        self.assertIn("NIKTO (OPTIONAL)", html)
        self.assertIn("NUCLEI (EXPLICIT OPT-IN)", html)
        self.assertNotIn("Failed adapters: PARTIAL", html)


class SL12AvailabilityAndPdfTests(unittest.TestCase):
    def test_http_508_availability_is_distinct_from_low_exploit_count(self):
        data = sample()
        summary = list(data["summary"])
        summary[2] = (
            "[ HTTP HEADERS OUTPUT ]\n"
            + "=" * 50 + "\n[PENX ADAPTER STATUS: COMPLETE; EVIDENCE: YES]\n"
            "HTTP 508 -> https://example.test/\nRetry-After: 14400\n"
        )
        data["summary"] = tuple(summary)
        with tempfile.TemporaryDirectory() as folder:
            html = Path(export_html(data, folder)).read_text(encoding="utf-8")
            pdf = Path(export_pdf(data, folder))
        self.assertIn("DEGRADED: HTTP 508", html)
        self.assertIn("AI risk is a separate assessment", html)
        self.assertIn("AI RISK ASSESSMENT", html)

    def test_compact_pdf_appendix_preserves_full_text_option(self):
        import os
        from unittest.mock import patch
        from penx_app.reporting.terminal_pdf import _pdf_ai_appendix_text
        original = "START\n" + "A" * 17000 + "\nFailed: NIKTO, HTTPX\n"
        with patch.dict(os.environ, {"PENX_PDF_AI_APPENDIX": "compact"}):
            compact = _pdf_ai_appendix_text(original)
        self.assertLess(len(compact), len(original))
        self.assertIn("APPENDIX COMPACTED", compact)
        self.assertIn("Failed: NIKTO, HTTPX", compact)
        with patch.dict(os.environ, {"PENX_PDF_AI_APPENDIX": "full"}):
            self.assertEqual(_pdf_ai_appendix_text(original), original)
        self.assertEqual(_pdf_ai_appendix_text("hello â€” world"), "hello -- world")


class DashboardLayoutTests(unittest.TestCase):
    def test_technical_dashboard_is_offline_and_has_coverage(self):
        with tempfile.TemporaryDirectory() as folder:
            html = Path(export_html(sample(), folder)).read_text(encoding="utf-8")
            self.assertIn('class="executive-metrics"', html)
            self.assertIn('id="coverage"', html)
            self.assertIn('class="scanner-grid"', html)
            self.assertIn('class="hero-status"', html)
            self.assertIn('href="#overview"', html)
            self.assertIn("Recommendation", html)
            self.assertNotIn('<script', html.lower())

    def test_executive_dashboard_excludes_technical_appendix(self):
        with tempfile.TemporaryDirectory() as folder:
            html = Path(export_html(sample(), folder, mode="executive")).read_text(encoding="utf-8")
            self.assertIn('id="coverage"', html)
            self.assertNotIn('id="appendix"', html)


if __name__ == "__main__":
    unittest.main(verbosity=2)
