"""Self-contained black/magenta/green PenX PDF report layout.

A4 portrait. Long observations flow onto subsequent pages; the original model
transcript stays in an explicitly unverified appendix. Built-in fonts only.
"""
from __future__ import annotations

import os
import re

from reportlab.lib import colors
from reportlab.lib.enums import TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable, KeepTogether, PageBreak, Paragraph, SimpleDocTemplate,
    Spacer, Table, TableStyle,
)

BG = "#09090B"
PANEL = "#141519"
LINE = "#4D505B"
TEXT = "#F0EFF7"
MUTED = "#ADB3C3"
MAGENTA = "#E00BD4"
GREEN = "#26E45E"
CYAN = "#43C9F2"
AMBER = "#EBD63A"
ORANGE = "#FF9352"


def _c(value):
    return colors.HexColor(value)


def _pdf_ai_appendix_text(source: str) -> str:
    """Normalize mojibake and compact the PDF-only audit transcript."""
    output = str(source or "")
    # Real SL#13 input contains 'â\x80\x94', the UTF-8 bytes for an em dash
    # decoded as Latin-1. Courier rendered the controls as black squares.
    def repair(match):
        try:
            return match.group(0).encode("latin-1").decode("utf-8")
        except UnicodeError:
            return match.group(0)
    output = re.sub(r"â[\x80-\xbf]{2}", repair, output)
    for broken, fixed in (("â€”", "--"), ("â€“", "-"), ("â†’", "->"),
                          ("â■■", "-"), ("—", "--"), ("–", "-"), ("→", "->"),
                          ("\uFFFD", "?")):
        output = output.replace(broken, fixed)
    if os.getenv("PENX_PDF_AI_APPENDIX", "compact").strip().lower() == "full":
        return output
    if len(output) <= 12000:
        return output
    return (output[:8000] + "\n\n[... PDF APPENDIX COMPACTED: full original AI audit "
            "remains in HTML and saved session ...]\n\n" + output[-3500:])

def render_terminal_pdf(r, destination, paragraph, severity, counts, summary, severity_colors, risk_colors, *, mode="technical"):
    """Render the same saved findings as HTML with PenX's console look."""
    page_w, page_h = A4
    margin = 16 * mm
    width = page_w - 2 * margin
    dark = os.getenv("PENX_PDF_THEME", "light").strip().lower() == "dark"
    page_bg = BG if dark else "#FFFFFF"
    panel_bg = PANEL if dark else "#F3F5F9"
    line_color = LINE if dark else "#C7CDD7"
    text_color = TEXT if dark else "#182231"
    muted_color = MUTED if dark else "#3D4A5D"
    green_color = GREEN if dark else "#127642"
    magenta_color = MAGENTA if dark else "#B021A4"
    styles = {
        "body": ParagraphStyle(
            "TerminalBody", fontName="Helvetica", fontSize=9.5, leading=14.4,
            textColor=_c(text_color), spaceAfter=6, splitLongWords=1,
        ),
        "small": ParagraphStyle(
            "TerminalSmall", fontName="Helvetica", fontSize=8.5, leading=12.5,
            textColor=_c(muted_color), splitLongWords=1,
        ),
        "label": ParagraphStyle(
            "TerminalLabel", fontName="Courier-Bold", fontSize=8.1, leading=12,
            textColor=_c(muted_color), splitLongWords=1,
        ),
        "section": ParagraphStyle(
            "TerminalSection", fontName="Courier-Bold", fontSize=11,
            leading=16, textColor=_c(green_color), spaceBefore=16,
            spaceAfter=6, keepWithNext=1, splitLongWords=1,
        ),
        "title": ParagraphStyle(
            "TerminalTarget", fontName="Courier-Bold", fontSize=16,
            leading=21, textColor=_c(text_color), splitLongWords=1,
        ),
        "card": ParagraphStyle(
            "TerminalCard", fontName="Helvetica-Bold", fontSize=10.5,
            leading=15, textColor=_c(text_color), splitLongWords=1,
        ),
        "appendix": ParagraphStyle(
            "TerminalAppendix", fontName="Helvetica", fontSize=9.0,
            leading=13, textColor=_c(muted_color), splitLongWords=1,
        ),
    }
    from penx_app.reporting.report_design import _finding_status

    doc = SimpleDocTemplate(
        str(destination), pagesize=A4, leftMargin=margin, rightMargin=margin,
        topMargin=43 * mm, bottomMargin=21 * mm,
        title=f"PenX Security Assessment - {r['target']}",
        author="PenX", subject="Authorized AI-assisted security assessment",
        pageCompression=1,
    )
    story = []
    safe = lambda v, key="body": paragraph(v, styles[key])

    # All colors come from fixed class labels, not model-generated strings.
    theme_severity = {
        "critical": "#C52342" if not dark else "#FF3D57",
        "high": "#A04F16" if not dark else ORANGE,
        "medium": "#876500" if not dark else AMBER,
        "low": "#16779A" if not dark else CYAN,
        "info": "#405A78" if not dark else "#B8C6D6",
        "unknown": muted_color,
    }
    risk_palette = (
        {"CRITICAL": "#C52342", "HIGH": "#A04F16",
         "MEDIUM": "#876500", "LOW": green_color}
        if not dark else
        {"CRITICAL": "#FF3D57", "HIGH": ORANGE, "MEDIUM": AMBER, "LOW": GREEN}
    )
    risk_color = risk_palette.get(r["risk"], muted_color)

    def section(number, name, count=None):
        head = f"[{number}]  {name.upper()}"
        if count is not None:
            head += f"  ({count})"
        story.append(safe(head, "section"))
        story.append(HRFlowable(width="100%", thickness=.65, color=_c(line_color),
                                spaceAfter=7))

    def field_row(name, val):
        return [safe(name, "label"), safe(val if val not in ("", None) else "-", "body")]

    def card(ref, title, detail, accent, meta=""):
        # Header fits in a flexible row; description is a separate Paragraph
        # and can split across pages, unlike a fixed-height six-column table.
        header = Table([[safe(ref, "label"), safe(title, "card")]],
                       colWidths=[17 * mm, width - 17 * mm],
                       hAlign="LEFT", splitByRow=1)
        header.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), _c(panel_bg)),
            ("LINEBEFORE", (0, 0), (0, -1), 3, _c(accent)),
            ("BOX", (0, 0), (-1, -1), .45, _c(line_color)),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 7),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ]))
        # Keep heading, metadata and first coherent paragraph on the same page.
        first = str(detail or "").split("\n", 1)[0]
        opening_text = first if len(first) <= 700 else first[:350].rsplit(" ", 1)[0]
        opening = [header, Spacer(1, 3)]
        if meta:
            opening.append(safe(meta, "small"))
        if opening_text:
            opening.append(safe(opening_text, "body"))
        story.append(KeepTogether(opening))
        remaining = str(detail or "")[len(opening_text):].lstrip()
        if remaining:
            story.append(safe(remaining, "body"))
        story.append(Spacer(1, 9))

    story.append(safe("AUTHORIZED SECURITY ASSESSMENT  /  LOCAL AI", "small"))
    story.append(Spacer(1, 5))
    story.append(safe(r["target"], "title"))
    story.append(safe("SCAN COVERAGE: " + r.get("coverage", {}).get("status", "UNKNOWN"), "label"))
    if r.get("availability"):
        story.append(safe("WEB AVAILABILITY: " + r["availability"] + " (separate from AI risk)", "small"))
    if r.get("coverage", {}).get("failed"):
        story.append(safe("Failed adapters: " + ", ".join(r["coverage"]["failed"]) + ". Absence of findings is inconclusive.", "small"))
    intel = r.get("intelligence", {})
    host_values = [
        ("SCANNED IP / EDGE", ", ".join(intel.get("addresses", [])) or "Not recorded"),
        ("REVERSE PROXY / CDN", intel.get("proxy", "Not established")),
        ("ORIGIN WEBSERVER", intel.get("webserver", "Not detected")),
        ("SCAN COVERAGE", r.get("coverage", {}).get("status", "UNKNOWN") + (": " + ", ".join(r["coverage"]["failed"]) if r.get("coverage", {}).get("failed") else "")),
    ]
    host_table = Table([[safe(k, "label"), safe(v, "small")] for k, v in host_values],
                       colWidths=[43 * mm, width - 43 * mm], hAlign="LEFT")
    host_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), _c(panel_bg)),
        ("INNERGRID", (0, 0), (-1, -1), .35, _c(line_color)),
        ("BOX", (0, 0), (-1, -1), .5, _c(line_color)),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(Spacer(1, 5))
    story.append(host_table)

    story.append(Spacer(1, 7))

    metadata = [
        [safe("SCAN DATE", "label"), safe("SESSION ID", "label")],
        [safe(r["date"], "body"), safe("SL#" + str(r["id"]), "body")],
        [safe("LOCAL MODEL", "label"), safe("GENERATED", "label")],
        [safe(r.get("model") or "Not recorded", "body"), safe(r["generated"], "body")],
    ]
    info = Table(metadata, colWidths=[width * .54, width * .46], hAlign="LEFT")
    info.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), _c(panel_bg)),
        ("BOX", (0, 0), (-1, -1), .6, _c(line_color)),
        ("INNERGRID", (0, 0), (-1, -1), .25, _c("#343640")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(info)
    section("+", "Scan summary")
    story.append(safe(summary(r), "body"))
    if intel.get("failed"):
        story.append(safe("PARTIAL SCAN: unavailable tools: " +
                          ", ".join(intel["failed"]) +
                          ". Results may be incomplete.", "small"))
    values = counts(r)
    kinds = ("critical","high","medium","low","info")
    nums = [
        [safe(k.upper(), "label") for k in kinds],
        [safe(str(values[k]), "card") for k in kinds],
    ]
    tiles = Table(nums, colWidths=[width/5]*5, hAlign="LEFT")
    tiles.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), _c(panel_bg)),
        ("BOX", (0, 0), (-1, -1), .5, _c(line_color)),
        ("INNERGRID", (0, 0), (-1, -1), .4, _c(line_color)),
        ("TOPPADDING", (0, 0), (-1, 0), 9),
        ("BOTTOMPADDING", (0, 1), (-1, 1), 9),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
    ]))
    confirmed = sum(
        _finding_status(v, r) == "Confirmed" for v in r["findings"]
    )
    potential = len(r["findings"]) - confirmed
    headline = Table([
        [safe("CONFIRMED", "label"), safe("POTENTIAL", "label"),
         safe("RECOMMENDATIONS", "label"), safe("INCOMPLETE SCANNERS", "label")],
        [safe(str(confirmed), "card"), safe(str(potential), "card"),
         safe(str(len(r["recommendations"])), "card"),
         safe(str(len(r["coverage"].get("failed", []))), "card")],
    ], colWidths=[width / 4] * 4, hAlign="LEFT")
    headline.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), _c(panel_bg)),
        ("BOX", (0, 0), (-1, -1), .5, _c(line_color)),
        ("INNERGRID", (0, 0), (-1, -1), .35, _c(line_color)),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(headline)
    story.append(Spacer(1, 8))
    story.append(safe(
        "AI risk is an overall assessment, not the number of verified "
        "vulnerabilities. Confirmed findings by severity (potential excluded):",
        "small"
    ))
    story.append(tiles)
    story.append(Spacer(1, 10))

    # Match the HTML dashboard: record the actual selected adapter coverage.
    completed = r["coverage"].get("completed", [])
    failed = r["coverage"].get("failed", [])
    scanner_names = list(dict.fromkeys(completed + failed))
    if scanner_names:
        section("+", "Scanner coverage", len(scanner_names))
        entries = [
            safe(f"{name}: {'INCOMPLETE' if name in failed else 'COLLECTED'}", "small")
            for name in scanner_names
        ]
        if len(entries) % 2:
            entries.append(safe("", "small"))
        rows = [entries[i:i + 2] for i in range(0, len(entries), 2)]
        status_table = Table(rows, colWidths=[width / 2] * 2, hAlign="LEFT")
        status_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), _c(panel_bg)),
            ("BOX", (0, 0), (-1, -1), .5, _c(line_color)),
            ("INNERGRID", (0, 0), (-1, -1), .35, _c(line_color)),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(status_table)
        story.append(safe(
            "COLLECTED means scanner evidence exists; it does not prove safety.",
            "small"
        ))

    section("01", "Findings", len(r["findings"]))
    if r.get("cve_warning"):
        story.append(safe("CVE IDENTITY ADVISORY: " + r["cve_warning"], "small"))
    if not r["findings"]:
        story.append(safe("No active findings recorded."))
    from penx_app.reporting.machine_reports import _finding as verified_finding
    for i, v in enumerate(r["findings"], 1):
        sev = severity(v[3])
        checked = verified_finding(v, r["raw_scan"], r["target"], False)
        status = ("Confirmed" if checked["confidence"] == "confirmed"
                  and checked["evidence_ref"] else "Potential")
        meta = (f"[{sev.upper()}]  Status: {status}  Confidence: {checked['confidence']}  "
                f"Port: {v[5] or '-'}  Service: {v[6] or '-'}")
        if checked["evidence_ref"]:
            evidence = ("\nEvidence reference: " + checked["evidence_ref"]
                        + "\nScanner quote: " + checked["evidence"][:280]
                        + "\nQuote matched, NOT proof of exploitability.")
        else:
            evidence = "\nEvidence reference: unverified (no exact scanner quote found)."
        card(f"F-{i:02d}", v[2] or "Untitled finding", (v[7] or "") + evidence,
             theme_severity[sev], meta)

    section("02", "Recommendations", len(r["recommendations"]))
    if not r["recommendations"]:
        story.append(safe("No recommendations recorded."))
    for i, v in enumerate(r["recommendations"], 1):
        card(f"R-{i:02d}", v[2] or "Recommendation", v[7] or "", CYAN)

    section("03", "Fixes and mitigations", len(r["fixes"]))
    if not r["fixes"]:
        story.append(safe("No remediation records saved."))
    for i, f in enumerate(r["fixes"], 1):
        card(f"M-{i:02d}", f"Finding #{f[2]} / NOT VERIFIED", f[3] or "",
             GREEN, f"Source: {f[4] or 'Not recorded'}")

    if r.get("comparison"):
        section("Δ", "Previous scan comparison")
        story.append(safe("Not observed does not mean remediated; compare scan scope and coverage.", "small"))
        story.append(safe(r["comparison"][:12000], "small"))

    if mode == "technical":
        section("04", "Historical AI exploit proposals / NOT EXECUTED", len(r["exploits"]))
        if not r["exploits"]:
            story.append(safe("No verified exploit execution recorded."))
        for i, e in enumerate(r["exploits"], 1):
            detail = f"Tool: {e[3] or '-'}\nPayload: {e[4] or '-'}\nResult: {e[5] or '-'}"
            if len(e)>6 and e[6]:
                detail += f"\nNotes: {e[6]}"
            card(f"E-{i:02d}", e[2] or "Unverified AI proposal",
                 "Unverified legacy model suggestion, NOT an executed attempt.\n" + detail, ORANGE)

        section("05", "Review / corrections", len(r["corrections"]))
        if not r["corrections"]:
            story.append(safe("No corrections recorded."))
        for i, c in enumerate(r["corrections"], 1):
            detail = f"Original: {c[4] or '-'}\nCorrected: {c[5] or '-'}\nReason: {c[6] or '-'}"
            card(f"C-{i:02d}", f"Finding #{c[2]}  /  {str(c[3]).upper()}", detail,
                 MAGENTA)

        if r["analysis"]:
            # Let the appendix start in remaining space after corrections. A
            # forced page break stranded the tail of C-03 alone on page 5.
            story.append(Spacer(1, 14))
            section("06", "Original AI output / UNVERIFIED")
            story.append(safe("Historical model text is not a verified finding. "
                              "The full original audit remains in HTML and the saved session.", "small"))
            story.append(Spacer(1, 6))
            # The printable report is concise by default. Historical raw
            # model text is still kept in HTML/session storage, or may be
            # explicitly included in a technical PDF with an environment flag.
            appendix_mode = os.getenv("PENX_PDF_AI_APPENDIX", "summary").strip().lower()
            if appendix_mode in ("compact", "full"):
                for line in _pdf_ai_appendix_text(r["analysis"]).splitlines():
                    if line.strip():
                        story.append(safe(line.strip(), "appendix"))
            else:
                story.append(safe(
                    "The full unverified historical AI transcript is omitted "
                    "from this printable PDF. It remains available in the "
                    "HTML report and saved session. To include it in future "
                    "PDFs, set PENX_PDF_AI_APPENDIX=compact or "
                    "PENX_PDF_AI_APPENDIX=full.",
                    "body",
                ))

    def decorate(canvas, document):
        canvas.saveState()
        canvas.setFillColor(_c(page_bg))
        canvas.rect(0, 0, page_w, page_h, stroke=0, fill=1)

        # Pixel/console-style logo with offset magenta echo.
        canvas.setFont("Courier-Bold", 31)
        canvas.setFillColor(_c("#E8B8E6" if not dark else "#750070"))
        canvas.drawString(margin+2, page_h-26*mm, "PENX")
        canvas.setFillColor(_c(magenta_color))
        canvas.drawString(margin, page_h-24*mm, "PENX")
        canvas.setFont("Courier", 8.1)
        canvas.setFillColor(_c(muted_color))
        canvas.drawString(margin, page_h-31*mm,
                          "AI Security Assessment | Local LLM | Windows 10/11")

        box_w, box_h = 51*mm, 14*mm
        right = page_w-margin
        top = page_h-12*mm
        canvas.setStrokeColor(_c(risk_color))
        canvas.setLineWidth(.85)
        canvas.rect(right-box_w, top-box_h, box_w, box_h, stroke=1, fill=0)
        canvas.setFont("Courier-Bold", 12)
        canvas.setFillColor(_c(risk_color))
        canvas.drawCentredString(right-box_w/2, top-9*mm,
                                 "RISK: "+str(r["risk"])[:12])

        canvas.setStrokeColor(_c(line_color))
        canvas.line(margin, page_h-36*mm, page_w-margin, page_h-36*mm)
        canvas.line(margin, 16*mm, page_w-margin, 16*mm)
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(_c(muted_color))
        canvas.drawString(margin, 11*mm, "PenX  |  AUTHORIZED USE ONLY  |  METATRON (MIT)")
        canvas.drawRightString(page_w-margin, 11*mm, f"SL#{r['id']}  |  {document.page:02d}")
        canvas.restoreState()

    doc.build(story, onFirstPage=decorate, onLaterPages=decorate)
    return str(destination)
