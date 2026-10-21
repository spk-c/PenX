"""Branded, print-safe PenX HTML and PDF assessment reports.

Presentation only: all values come from the committed session. HTML is escaped,
PDF paragraphs escape ReportLab markup; raw model output is explicitly unverified.
No remote fonts, scripts, images or other network dependencies.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime
from html import escape
from penx_app.cli.terminal_theme import TERMINAL_CSS
from penx_app.reporting.scan_coverage import coverage
from penx_app.reporting.terminal_pdf import render_terminal_pdf
from pathlib import Path
import re

from reportlab.platypus import Paragraph

INK = "#121924"
NAVY = "#182435"
RED = "#ec4c51"
MUTED = "#637286"
BORDER = "#dbe2e9"
PAPER = "#f5f7fa"
WHITE = "#ffffff"
SEVERITY = {
    "critical": ("#b91c1c", "#fef2f2"),
    "high": ("#c2410c", "#fff7ed"),
    "medium": ("#a16207", "#fefce8"),
    "low": ("#23734e", "#ecfdf5"),
    "info": ("#2676aa", "#eff8ff"),
    "unknown": ("#637286", "#eef2f6"),
}
RISK = {"CRITICAL": "#FF3D57", "HIGH": "#FF9352", "MEDIUM": "#EBD63A",
        "LOW": "#26E45E", "UNKNOWN": "#ABB3C3"}


def _s(value, limit=None):
    value = str(value if value is not None else "")
    value = value.replace("\x00", "")
    return value[:limit] if limit is not None else value


def _h(value):
    return escape(_s(value), quote=True)


def _p(value, style):
    # Text from scanners and models must never become ReportLab XML.
    return Paragraph(_h(value).replace("\n", "<br/>"), style)



def _scan_intelligence(raw):
    """Show only facts present in saved Nmap/HTTP evidence; do not resolve live DNS."""
    import ipaddress
    raw = _s(raw)
    addresses = []
    for line in raw.splitlines():
        if not re.search(r"(Nmap scan report for|Scanning |Host: )", line, re.I):
            continue
        for value in re.findall(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])", line):
            try:
                ipaddress.ip_address(value)
            except ValueError:
                continue
            if value not in addresses:
                addresses.append(value)
    proxy = "Cloudflare" if re.search(r"(?:server:\s*cloudflare|Cloudflare http proxy|Server\[cloudflare\])", raw, re.I) else "Not established"
    servers = [name for name, pat in (
        ("nginx", r"(?:Server:\s*nginx|HTTPServer\[nginx)"),
        ("Apache", r"(?:Server:\s*Apache|HTTPServer\[Apache)"),
        ("IIS", r"(?:Microsoft-IIS/|HTTPServer\[Microsoft-IIS)"),
    ) if re.search(pat, raw, re.I)]
    failed = [name for name, pattern in (
        ("Nikto", r"(?:XML::Writer|Nikto[^\n]{0,100}(?:failed|unavailable|error)|\[FAIL\][^\n]*Unable to connect|Unable to connect to [^\n]+:\d+)"),
        ("Nmap", r"Nmap[^\n]{0,100}(?:failed|unavailable|error)"),
        ("WhatWeb", r"WhatWeb[^\n]{0,100}(?:failed|unavailable|error)"),
    ) if re.search(pattern, raw, re.I)]
    return {"addresses": addresses[:6], "proxy": proxy,
            "webserver": ", ".join(servers) if servers else "Origin not identified",
            "failed": failed}


def _finding_status(item, report=None):
    """Use the same scanner-quote validation as PDF/SARIF when available."""
    if str(item[4] or "").lower() not in ("confirmed", "verified"):
        return "Potential"
    if report is None or "raw_scan" not in report:
        return "Confirmed"  # Legacy callers with no evidence context.
    from penx_app.reporting.machine_reports import _finding as verified_finding
    checked = verified_finding(item, report["raw_scan"], report["target"], False)
    return ("Confirmed" if checked["confidence"] == "confirmed"
            and checked["evidence_ref"] else "Potential")


def _display_recommendations(rows):
    """Normalize and collapse duplicate saved advice without modifying audit rows."""
    seen = {}
    ordered = []
    for original in rows:
        item = list(original)
        for idx in (2, 7):
            item[idx] = re.sub(r"(?i)(FlyingPress) theme", r"\1 plugin", _s(item[idx]))
        title = _s(item[2]).casefold()
        body = _s(item[7]).casefold()
        duplicate_key = ("flyingpress-version" if "flyingpress" in title and
                         ("version" in title or "version" in body)
                         else ("exact", re.sub(r"\W+", " ", title).strip()))
        if duplicate_key in seen:
            previous_index = seen[duplicate_key]
            previous = ordered[previous_index]
            # Prefer the more actionable wording when a saved session
            # includes both "version unconfirmed" and "confirm version".
            if title.startswith(("confirm", "verify")) and not _s(previous[2]).lower().startswith(("confirm", "verify")):
                ordered[previous_index] = tuple(item)
        else:
            seen[duplicate_key] = len(ordered)
            ordered.append(tuple(item))
    return ordered


def _availability_status(raw_scan):
    """Separate target availability from AI security severity in saved reports."""
    raw = str(raw_scan or "")
    if re.search(r"(?im)^HTTP\s+508\b|508 Resource Limit Is Reached", raw):
        return "DEGRADED: HTTP 508 (resource limit)"
    if re.search(r"(?im)^HTTP\s+503\b|503 Service Unavailable", raw):
        return "DEGRADED: HTTP 503"
    return "Not established by saved evidence"


def _report(data):
    h = data["history"]
    summary = data.get("summary")
    if not h or not summary:
        raise ValueError("A completed session is required for report export")
    findings = [v for v in data.get("vulns", ()) if str(v[4] or "").lower() != "recommendation"]
    recommendations = _display_recommendations([v for v in data.get("vulns", ()) if str(v[4] or "").lower() == "recommendation"])
    risk = _s(summary[4] or "UNKNOWN").upper()
    return {
        "id": h[0], "target": _s(h[1]), "date": _s(h[2]),
        "risk": risk, "analysis": _s(summary[3]),
        "coverage": coverage(data.get('scan_result') or _s(summary[2])),
        "availability": _availability_status(summary[2]),
        "model": _s(summary[5] if len(summary) > 5 else "Not recorded"),
        "intelligence": _scan_intelligence(summary[2] if len(summary) > 2 else ""),
        "raw_scan": _s(summary[2] if len(summary) > 2 else ""),
        "comparison": _s(data.get("comparison") or ""),
        "findings": findings, "recommendations": recommendations,
        "fixes": data.get("fixes", ()), "exploits": data.get("exploits", ()),
        "corrections": data.get("corrections", ()),
        "generated": datetime.now().strftime("%Y-%m-%d %H:%M"),
    }


def _path(report, folder, suffix):
    out = Path(folder)
    out.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^A-Za-z0-9_-]+", "_", report["target"])[:70].strip("_") or "target"
    return out / f"penx_SL{report['id']}_{safe}.{suffix}"


def _severity(s):
    return _s(s or "unknown").lower() if _s(s or "").lower() in SEVERITY else "unknown"


def _legacy_cve_warning(report):
    """Flag historical saved AI wording without silently rewriting DB records."""
    text = "\n".join(str(v[7] or "") for v in report.get("findings", ()))
    if re.search(r"(?i)regresshion.{0,40}CVE-2023-48795|CVE-2023-48795.{0,40}regresshion", text):
        return ("CVE identifier correction for this saved assessment: "
                "CVE-2023-48795 refers to Terrapin, not regreSSHion. "
                "regreSSHion is CVE-2024-6387. "
                "A bare OpenSSH version banner cannot prove or exclude Terrapin; "
                "verify negotiated algorithms and vendor fixes. "
                "Original historical text is preserved for audit.")
    if re.search(r"OpenSSH\s+7\.4", text, re.I) and re.search(
            r"CVE-2024-6387|CVE-2023-38408", text, re.I):
        return ("HISTORICAL SSH CVE WARNING: The OpenSSH 7.4 server banner "
                "does not establish regreSSHion CVE-2024-6387; upstream 7.4 "
                "is outside the affected regression range. CVE-2023-38408 "
                "concerns ssh-agent / PKCS#11 forwarding, not this SSH listener. "
                "This saved historical finding and severity were not re-reviewed; "
                "verify the actual vendor package and client configuration.")
    return ""


def _counts(report):
    c = Counter(_severity(v[3]) for v in report["findings"] if _finding_status(v, report) == "Confirmed")
    return {name: c[name] for name in ("critical", "high", "medium", "low", "info")}


def _summary(report):
    # Persisted raw AI text is intentionally not parsed into new "confirmed" facts.
    return (
        f"{sum(_finding_status(v, report) == 'Confirmed' for v in report['findings'])} confirmed, "
        f"{sum(_finding_status(v, report) != 'Confirmed' for v in report['findings'])} potential finding(s), "
        f"{len(report['recommendations'])} recommendation(s). "
        "Only observations retained in the saved assessment are shown below. "
        "Version disclosures or edge-proxy banners do not by themselves prove exploitability."
    )


def export_html(data: dict, output_dir: str, *, mode: str = "technical") -> str:
    if mode not in ("technical", "executive"):
        raise ValueError("Invalid report mode")
    r = _report(data)
    dst = _path(r, output_dir, "html" if mode == "technical" else "executive.html")
    counts = _counts(r)
    red = RED
    risk_color = RISK.get(r["risk"], RISK["UNKNOWN"])

    def badge(sev):
        label = _severity(sev)
        return f'<span class="badge sev-{label}">{_h(label.upper())}</span>'

    def finding(item, i):
        title = _h(item[2] or "Untitled observation")
        desc = _h(item[7] or "No description recorded.")
        confidence = _h(item[4] or "unknown")
        status = _h(_finding_status(item, r))
        from penx_app.reporting.machine_reports import _finding as verified_finding
        source = verified_finding(item, r["raw_scan"], r["target"], False)
        evidence = (source["evidence"][:300] if source["evidence_ref"]
                    else "No exact quoted scanner evidence verified; human review required.")
        evidence_ref = source["evidence_ref"] or "unverified"
        from penx_app.reporting.finding_trace import finding_trace
        trace = finding_trace(item, data)
        scanner_name = trace["scanner"] or "Unattributed"
        scanner_version = trace["scanner_version"] or "Not recorded"
        scan_date = trace["recorded_at"] or "Unknown"
        port = _h(item[5] or "-")
        service = _h(item[6] or "-")
        return f"""<article class="finding severity-{_severity(item[3])} status-{status.lower()}">
          <div class="finding-top"><span class="item-number">[F-{i:02d}]</span>
            <h3>{title}</h3>{badge(item[3])}</div>
          <div class="finding-meta"><span>Status: {status}</span><span>Confidence: {confidence}</span>
            <span>Port: {port}</span><span>Service: {service}</span></div>
          <p>{desc}</p><details class="evidence"><summary>Saved scan evidence</summary><pre>{_h(evidence)}</pre><small>Source: {_h(scanner_name)} · Scanner version: {_h(scanner_version)} · Scan date: {_h(scan_date)} · Evidence reference: {_h(evidence_ref)} · Exact quote matching is not confirmation of exploitability.</small></details></article>"""

    def rec(item, i):
        return f"""<article class="rec"><span class="rec-index">[R-{i:02d}]</span>
          <div class="rec-content"><small class="rec-kind">ACTION / REVIEW REQUIRED</small><h3>{_h(item[2] or "Recommendation")}</h3>
          <p>{_h(item[7] or "No description recorded.")}</p></div></article>"""

    def row(label, text, mark=""):
        return f'<div class="detail-row"><span class="detail-label">{_h(label)}</span><div>{_h(text or "-")}</div>{mark}</div>'

    summary_metrics = "".join(
        f'<div class="metric metric-{k}"><span>{_h(k.upper())}</span><strong>{v}</strong></div>'
        for k, v in counts.items()
    )
    findings = "".join(finding(x, i) for i, x in enumerate(r["findings"], 1))
    intel = r["intelligence"]
    host_items = (
        ("Scanned IP / edge", ", ".join(intel["addresses"]) or "Not recorded"),
        ("Reverse proxy / CDN", intel["proxy"]),
        ("Origin webserver", intel["webserver"]),
        ("Scanner coverage", r["coverage"]["status"] + (": " + ", ".join(r["coverage"].get("failed", [])) if r["coverage"].get("failed") else "")),
        ("Web availability", r["availability"]),
    )
    host_html = "".join(
        f'<div class="host-item"><small>{_h(label)}</small><strong>{_h(value)}</strong></div>'
        for label, value in host_items
    )
    warning_html = ('<p class="coverage-note">' + _h(_legacy_cve_warning(r)) + '</p>'
                    if _legacy_cve_warning(r) else "")
    limitations = ("PARTIAL SCAN: " + ", ".join(r["coverage"].get("failed", [])) +
                   " unavailable; security assessment is incomplete.") if r["coverage"].get("failed") else (
                   "Coverage reflects saved scan evidence only; no reported finding does not imply safety.")

    scanner_cards = "".join(
        f'<div class="scanner-chip"><span class="scanner-state {("state-failed" if name in r["coverage"].get("failed", []) else "state-ok")}"></span>'
        f'<span>{_h(name)}</span><strong>{("INCOMPLETE" if name in r["coverage"].get("failed", []) else "COLLECTED")}</strong></div>'
        for name in dict.fromkeys(r["coverage"].get("completed", []) + r["coverage"].get("failed", []))
    ) or '<p class="empty">No structured scanner coverage recorded.</p>'
    overview_tiles = (
        ("Confirmed", sum(_finding_status(v, r) == "Confirmed" for v in r["findings"])),
        ("Potential", sum(_finding_status(v, r) != "Confirmed" for v in r["findings"])),
        ("Recommendations", len(r["recommendations"])),
        ("Incomplete scanners", len(r["coverage"].get("failed", []))),
    )
    overview_html = "".join(
        f'<div class="overview-tile"><strong>{number}</strong><span>{_h(label)}</span></div>'
        for label, number in overview_tiles
    )
    recommendations = "".join(rec(x, i) for i, x in enumerate(r["recommendations"], 1))
    fixes = "".join(
        f'<article class="record"><h3>Mitigation for finding #{_h(f[2])} · NOT VERIFIED</h3>'
        + row("Remediation", f[3]) + row("Source", f[4]) + "</article>"
        for f in r["fixes"]
    )
    exploits = "".join(
        f'<article class="record"><h3>{_h(e[2] or "Unverified AI proposal")}</h3>'
        + '<p class="caution">Legacy model suggestion only; no exploit execution was verified.</p>'
        + row("Tool", e[3]) + row("Payload", e[4])
        + row("Result", e[5]) + row("Notes", e[6] if len(e) > 6 else "") + "</article>"
        for e in r["exploits"]
    )
    corrections = "".join(
        f'<article class="record review"><h3>[C-{i:02d}] Finding #{_h(c[2])} · {_h(_s(c[3]).upper())}</h3>'
        + row("Original", c[4]) + row("Corrected", c[5])
        + row("Reason", c[6]) + "</article>"
        for i, c in enumerate(r["corrections"], 1)
    )
    # The executive variant omits technical exploit transcripts and raw model text.
    comparison_nav = '<a href="#comparison">Δ / Scan comparison</a>' if r["comparison"] else ""
    technical_nav = "" if mode == "executive" else '<a href="#activity">04 / AI proposals</a><a href="#review">05 / Review</a><a href="#appendix">06 / AI appendix</a>'
    technical_sections = "" if mode == "executive" else f"""<section id="activity"><div class="section-head"><span class="section-no">[04]</span><h2>Historical AI exploit proposals - NOT EXECUTED</h2><small>{len(r['exploits'])} entries</small></div>
{exploits if exploits else '<p class="empty">No verified exploit execution recorded.</p>'}</section>
<section id="review"><div class="section-head"><span class="section-no">[05]</span><h2>Corrections &amp; review</h2><small>{len(r['corrections'])} entries</small></div>
{corrections if corrections else '<p class="empty">No corrections recorded.</p>'}</section>
<section id="appendix"><div class="section-head"><span class="section-no">[06]</span><h2>Original AI output</h2><small>UNVERIFIED APPENDIX</small></div>
<p class="caution">Historical model text is not an active finding. It may include draft claims later rejected or reclassified during review.</p>
<details><summary>Expand original model output</summary><div class="log">{_h(r['analysis']) if r['analysis'] else 'No AI output recorded.'}</div></details></section>"""
    comparison_section = (
        '<section id="comparison"><div class="section-head"><span class="section-no">[Δ]</span>'
        '<h2>Previous scan comparison</h2></div><pre class="comparison-text">'
        + _h(r["comparison"]) + '</pre></section>'
    ) if r["comparison"] else ""
    content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">
<title>PenX | Security Assessment | {_h(r['target'])}</title>
<style>
{TERMINAL_CSS}
</style>
</head><body><main class="container">
<header class="topbar">
 <div class="brand"><div class="brandmark">X</div><div><div class="brandname" aria-label="PenX">PEN<em>X</em></div>
 <div class="brandcap">LOCAL AI / SECURITY RECON | AI Security Assessment | Local LLM | Windows 10/11</div></div></div>
 <div class="top-meta">ASSESSMENT REPORT<strong>SESSION SL#{_h(r['id'])}</strong></div>
</header>
<div class="hero"><div><div class="eyebrow">&gt; PENX / SECURITY INTELLIGENCE</div>
 <h1>{_h(r['target'])}</h1><p>Authorized security assessment · Local AI assisted analysis</p><div class="hero-status">Scan coverage: <strong>{_h(r["coverage"]["status"])}</strong></div><div class="host-grid">{host_html}</div></div>
 <div class="risk-panel" style="--risk-color:{risk_color}"><span>AI RISK ASSESSMENT</span><strong>RISK: {_h(r['risk'])}</strong></div></div>
<div class="metadata">
 <div class="meta"><small>Scan timestamp</small><strong>{_h(r['date'])}</strong></div>
 <div class="meta"><small>Session</small><strong>SL# {_h(r['id'])}</strong></div>
 <div class="meta"><small>Report generated</small><strong>{_h(r['generated'])}</strong></div>
 <div class="meta"><small>Local model</small><strong>{_h(r['model'])}</strong></div>
</div>
<section class="overview" id="overview"><div class="overview-header">
 <h2>Scan summary</h2><span class="mono">REPORT / 01</span></div>
 <div class="executive-metrics">{overview_html}</div><p>{_h(_summary(r))}</p><p class="risk-explanation">AI risk is an overall model assessment. It is not calculated by counting confirmed vulnerabilities. Confirmed and potential findings are intentionally shown separately; incomplete scanners limit the conclusions.</p><p>Scanner coverage: {_h(r["coverage"]["status"])}; incomplete: {_h(", ".join(r["coverage"]["failed"]) or "none")}</p><p class="coverage-note">Availability: {_h(r["availability"])}. AI risk is a separate assessment, not a confirmed exploitable vulnerability count.</p><p class="coverage-note">{_h(limitations)}</p>{warning_html}<p class="metric-caption">Confirmed findings by severity (potential findings are counted separately above)</p><div class="metrics">{summary_metrics}</div></section>
<section class="coverage-panel" id="coverage"><div class="section-head"><span class="section-no">[+]</span><h2>Scanner coverage</h2><small>{_h(r["coverage"]["status"])}</small></div>
<p class="coverage-intro">These statuses describe collected evidence, not proof of security. Unselected scanners are not included.</p>
<div class="scanner-grid">{scanner_cards}</div></section>
<nav aria-label="Report sections"><a href="#overview">Overview</a><a href="#coverage">Scanner coverage</a><a href="#findings">01 / Findings</a><a href="#recommendations">02 / Recommendations</a>
<a href="#mitigations">03 / Mitigations</a>{comparison_nav}{technical_nav}</nav>
<section id="findings"><div class="section-head"><span class="section-no">[01]</span><h2>Confirmed &amp; potential findings</h2><small>{len(r['findings'])} entries</small></div>
<div class="report-filters" aria-label="Filter findings"><label><input type="radio" name="finding-filter" checked> All</label><label><input type="radio" name="finding-filter"> Confirmed</label><label><input type="radio" name="finding-filter"> Potential</label></div>
<div class="findings-grid">{findings if findings else '<p class="empty">No active findings recorded.</p>'}</div></section>
<section id="recommendations"><div class="section-head"><span class="section-no">[02]</span><h2>Recommendations</h2><small>{len(r['recommendations'])} entries</small></div>
<div class="recommendations-grid">{recommendations if recommendations else '<p class="empty">No recommendations recorded.</p>'}</div></section>
<section id="mitigations"><div class="section-head"><span class="section-no">[03]</span><h2>Remediation guidance (completion unverified)</h2><small>{len(r['fixes'])} entries</small></div>
{fixes if fixes else '<p class="empty">No remediation records saved.</p>'}</section>
{comparison_section}
{technical_sections}
<footer><span>PenX / AI Security Assessment · Authorized use only</span>
<span>Inspired by <a href="https://github.com/sooryathejas/METATRON">METATRON (MIT)</a> · SL#{_h(r['id'])}</span></footer>
</main></body></html>"""
    dst.write_text(content, encoding="utf-8")
    return str(dst)


def export_pdf(data: dict, output_dir: str, *, mode: str = "technical") -> str:
    if mode not in ("technical", "executive"):
        raise ValueError("Invalid report mode")
    """Generate a dark PenX terminal PDF with magenta branding and green labels."""
    r = _report(data)
    r["cve_warning"] = _legacy_cve_warning(r)
    dst = _path(r, output_dir, "pdf" if mode == "technical" else "executive.pdf")
    return render_terminal_pdf(r, dst, _p, _severity, _counts, _summary, SEVERITY, RISK, mode=mode)
