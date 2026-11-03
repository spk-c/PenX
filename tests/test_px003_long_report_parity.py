"""PX-003: long saved reports retain identical accepted findings in every output.

All records are synthetic and local. The PDF story is inspected directly to
prove content parity even without a platform-specific PDF text extractor.
"""
from __future__ import annotations

from pathlib import Path
import json
import re
import tempfile
import unittest
from unittest.mock import patch

from reportlab.platypus import KeepTogether, Paragraph, Table

from penx_app.reporting.export import export_html, export_pdf
from penx_app.reporting.machine_reports import report_payload, sarif_payload
from penx_app.reporting.report_view import ReportView


def session(n: int = 1000) -> dict:
    assert 1 <= n <= 1000
    sl = 904
    observed = "443/tcp open https"
    rows = []
    for i in range(1, n + 1):
        label = f"FixtureReport-{i:04d}"
        confirmed = i == 1
        desc = ("Offline scanner quotation. Evidence: " + observed
                if confirmed else "Offline review only; scanner applicability unverified.")
        rows.append((i, sl, label, "high" if i % 9 == 0 else "low",
                     "confirmed" if confirmed else "possible", str(i + 1000), "https",
                     desc))
    rejected = tuple(i for i in range(37, n + 1, 97))
    corrections = [(5000+i, sl, i, "hallucination", "", "",
                    "No evidence for this synthetic claim", "2026-11-03")
                   for i in rejected]
    # Recommendation rows are excluded from security findings; they are
    # retained separately across all report formats.
    recommendations = [(n+i, sl, f"FixtureRecommendation-{i:02d}", "info",
                        "recommendation", "", "", "Document a configuration review")
                       for i in range(1, 13)]
    return {
        "history": (sl, "fixture.invalid", "2026-11-03", "active"),
        "summary": (1, sl, "[ NMAP OUTPUT ]\n"
                    "[PENX ADAPTER STATUS: COMPLETE; EVIDENCE: YES]\n" + observed,
                    "UNVERIFIED SYNTHETIC MODEL TEXT",
                    "UNKNOWN", "fixture-local", "2026-11-03"),
        "vulns": rows + recommendations,
        "corrections": corrections,
        "fixes": [(3000+i, sl, i, f"Review fixture {i}", "synthetic")
                  for i in range(1, n+1, 32)],
        "exploits": [],
    }


def story_text(node) -> list[str]:
    if isinstance(node, Paragraph):
        return [node.text]
    if isinstance(node, Table):
        result = []
        for row in node._cellvalues:
            for cell in row:
                result.extend(story_text(cell))
        return result
    if isinstance(node, (list, tuple)):
        result = []
        for item in node:
            result.extend(story_text(item))
        return result
    if isinstance(node, KeepTogether) or hasattr(node, "_content"):
        return story_text(node._content)
    return []


class Px003LongReportParityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="penx-px003-long-")
        self.addCleanup(self.tmp.cleanup)

    def test_one_thousand_rows_remain_reviewed_and_equal_across_four_formats(self):
        source = session()
        original = tuple(source["vulns"])
        view = ReportView.from_session(source)
        approved = {f"FixtureReport-{row[0]:04d}" for row in view.active_findings
                    if row[0] <= 1000}
        rejected = {f"FixtureReport-{row[2]:04d}" for row in source["corrections"]}
        self.assertEqual(len(approved), 1000 - len(rejected))
        self.assertFalse(approved.intersection(rejected))

        machine = report_payload(source)
        sarif = sarif_payload(source)["runs"][0]
        self.assertEqual(len(machine["findings"]), len(approved)+12)
        self.assertEqual(len(sarif["results"]), len(approved))
        self.assertEqual({f["name"] for f in machine["findings"] if f["id"] <= 1000},
                         approved)

        html = Path(export_html(source, self.tmp.name)).read_text(encoding="utf-8")
        displayed = re.findall(r"FixtureReport-\d{4}", html)
        self.assertEqual(set(displayed), approved)
        self.assertEqual(len(displayed), len(approved))
        self.assertNotIn("UNVERIFIED SYNTHETIC MODEL TEXT</h3>", html)

        with patch("penx_app.reporting.terminal_pdf.SimpleDocTemplate") as builder:
            export_pdf(source, self.tmp.name)
        builder.return_value.build.assert_called_once()
        story = builder.return_value.build.call_args.args[0]
        text = "\n".join(story_text(story))
        pdf_labels = re.findall(r"FixtureReport-\d{4}", text)
        self.assertEqual(set(pdf_labels), approved)
        self.assertEqual(len(pdf_labels), len(approved))
        self.assertNotIn("UNVERIFIED SYNTHETIC MODEL TEXT", text)
        for title in rejected:
            self.assertNotIn(title, text + html)
        for i in range(1, 13):
            title=f"FixtureRecommendation-{i:02d}"
            self.assertIn(title, html)
            self.assertIn(title, text)
        self.assertEqual(tuple(source["vulns"]), original)

    def test_real_pdf_paginating_250_reviewed_rows(self):
        # This is a builder and pagination smoke, not a human visual sign-off.
        source=session(250)
        path=Path(export_pdf(source, self.tmp.name))
        data=path.read_bytes()
        self.assertTrue(data.startswith(b"%PDF-"))
        self.assertGreater(len(data), 8000)
        self.assertIn(b"%%EOF", data[-64:])
        self.assertGreater(data.count(b"/Type /Page"), 5)

    def test_unpaired_surrogate_is_replaced_not_exported_as_html_or_pdf_markup(self):
        source=session(2)
        row=list(source["vulns"][1])
        row[2]="FixtureReport-0002" + chr(0xD800) + "<img src=x onerror=alert(1)>"
        row[7]="Untrusted body " + chr(0xDC00) + "<script>eval(1)</script>"
        source["vulns"][1]=tuple(row)
        # Machine consumers must get valid UTF-8 too; json.dumps alone can
        # hide invalid surrogate codepoints via ASCII escape sequences.
        machine=report_payload(source)
        sarif=sarif_payload(source)
        badname=machine["findings"][1]["name"]
        self.assertIn("FixtureReport-0002", badname)
        self.assertNotIn(chr(0xD800), badname)
        self.assertNotIn(chr(0xDC00), badname)
        for payload in (machine, sarif):
            encoded=json.dumps(
                payload, ensure_ascii=False).encode("utf-8", errors="strict")
            self.assertGreater(len(encoded), 100)
        html=Path(export_html(source, self.tmp.name)).read_text(encoding="utf-8")
        self.assertIn("FixtureReport-0002", html)
        self.assertNotIn("<script>eval(1)</script>", html)
        self.assertNotIn("<img src=x onerror=alert(1)>", html)
        self.assertNotIn(chr(0xD800), html)
        self.assertNotIn(chr(0xDC00), html)
        with patch("penx_app.reporting.terminal_pdf.SimpleDocTemplate") as builder:
            export_pdf(source, self.tmp.name)
        pdf = "\n".join(story_text(builder.return_value.build.call_args.args[0]))
        self.assertIn("FixtureReport-0002", pdf)
        self.assertNotIn("<script>eval(1)</script>", pdf)
        self.assertNotIn(chr(0xD800), pdf)
        self.assertNotIn(chr(0xDC00), pdf)


if __name__=="__main__":
    unittest.main()
