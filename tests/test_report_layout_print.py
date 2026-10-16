"""Offline regression checks for the SL#14/15 report layout improvements."""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from reportlab.platypus import Paragraph, Table
from penx_app.reporting.report_design import export_html, export_pdf


def fixture():
    raw = (
        "[ NMAP OUTPUT ]\n"
        + "=" * 50 + "\n"
        "[PENX ADAPTER STATUS: COMPLETE; EVIDENCE: YES]\n"
        "443/tcp open https\n"
        "[ NUCLEI OUTPUT ]\n"
        + "=" * 50 + "\n"
        "[PENX ADAPTER STATUS: PARTIAL; EVIDENCE: NO]\n"
        "[!] Timed out after 240s\n"
    )
    return {
        "history": (15, "authorized.example.test", "2026-10-16 00:20:25", "active"),
        "summary": (15, 15, raw, "UNVERIFIED TRANSCRIPT: MODEL RAW OUTPUT",
                    "LOW", "local-qwen"),
        "vulns": [
            (104, 15, "Review mail authentication", "low", "possible",
             "53", "DNS", "Verify the relevant TXT records."),
            (105, 15, "Verify component versions", "info", "recommendation",
             "", "", "Check admin inventory before assigning a CVE."),
        ],
        "fixes": [], "exploits": [], "corrections": [],
    }


def inspect_pdf(data, folder, settings=None):
    """Capture real flowables and PDF page-decoration calls, without a renderer."""
    with patch.dict(os.environ, settings or {}, clear=False):
        with patch("penx_app.reporting.terminal_pdf.SimpleDocTemplate") as template:
            export_pdf(data, folder)
    options = template.call_args.kwargs
    build = template.return_value.build.call_args
    elements = build.args[0]
    canvas = Mock()
    build.kwargs["onFirstPage"](canvas, SimpleNamespace(page=1))
    texts = []
    for element in elements:
        if isinstance(element, Paragraph):
            texts.append(element.text)
        elif isinstance(element, Table):
            for row in element._cellvalues:
                texts.extend(cell.text for cell in row if isinstance(cell, Paragraph))
    return options, canvas, texts, elements


class PrintableReportLayoutTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_html_layout_stays_compact_with_four_metadata_fields(self):
        html = Path(export_html(fixture(), self.tmp.name)).read_text(encoding="utf-8")
        self.assertIn("repeat(auto-fit,minmax(min(100%,320px),1fr))", html)
        self.assertIn(".rec-index{flex:none;white-space:nowrap", html)
        self.assertEqual(html.count('<div class="meta"><small>'), 4)
        self.assertIn("AI risk is an overall model assessment", html)
        self.assertIn('class="finding severity-low status-potential"', html)
        self.assertIn("NUCLEI", html)
        self.assertNotIn("<script", html.lower())

    def test_default_pdf_uses_light_paper_and_legible_body(self):
        _, canvas, texts, elements = inspect_pdf(fixture(), self.tmp.name,
                                                 {"PENX_PDF_THEME": "light"})
        bg = canvas.setFillColor.call_args_list[0].args[0]
        self.assertEqual(bg.hexval().lower(), "0xffffff")
        body_styles = [part.style for part in elements
                       if isinstance(part, Paragraph) and part.style.name == "TerminalBody"]
        self.assertTrue(body_styles)
        self.assertTrue(all(style.fontSize >= 9 for style in body_styles))
        self.assertIn("POTENTIAL", texts)
        self.assertIn("CONFIRMED", texts)
        self.assertTrue(any("NUCLEI: INCOMPLETE" in s for s in texts))
        self.assertTrue(any("NMAP: COLLECTED" in s for s in texts))
        self.assertTrue(any("AI risk is an overall assessment" in s for s in texts))

    def test_original_ai_text_is_not_printed_unless_requested(self):
        _, _, texts, _ = inspect_pdf(fixture(), self.tmp.name,
                                    {"PENX_PDF_AI_APPENDIX": "summary"})
        self.assertFalse(any("UNVERIFIED TRANSCRIPT: MODEL RAW OUTPUT" in s for s in texts))
        self.assertTrue(any("full unverified historical AI transcript is omitted" in s for s in texts))

    def test_full_audit_appendix_remains_explicitly_available(self):
        _, _, texts, _ = inspect_pdf(fixture(), self.tmp.name,
                                    {"PENX_PDF_AI_APPENDIX": "full"})
        self.assertTrue(any("UNVERIFIED TRANSCRIPT: MODEL RAW OUTPUT" in s for s in texts))

    def test_dark_pdf_remains_supported(self):
        _, canvas, _, _ = inspect_pdf(fixture(), self.tmp.name,
                                      {"PENX_PDF_THEME": "dark"})
        bg = canvas.setFillColor.call_args_list[0].args[0]
        self.assertEqual(bg.hexval().lower(), "0x09090b")

    def test_real_a4_pdf_is_generated_in_both_modes(self):
        for mode in ("technical", "executive"):
            path = Path(export_pdf(fixture(), self.tmp.name, mode=mode))
            self.assertTrue(path.read_bytes().startswith(b"%PDF-"))
            self.assertGreater(path.stat().st_size, 2000)


if __name__ == "__main__":
    unittest.main(verbosity=2)
