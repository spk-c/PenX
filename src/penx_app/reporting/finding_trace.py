"""Bounded, conservative evidence attribution for saved assessment findings.

This module does not make network requests or promote an AI claim to proof of a
vulnerability. Unattributed evidence and missing scanner metadata remain unknown.
"""
from __future__ import annotations

import re

from penx_app.intelligence.source_verification import evidence_in_scan
from penx_app.reporting.scan_coverage import HEAD

_EVIDENCE_LINE = re.compile(r"(?m)^Evidence: (.{1,2000})$")
_VERSION = {
    "NMAP": re.compile(r"(?im)^Nmap(?: version)?[ /]+(\d+(?:\.\d+){1,3})\b"),
    "NUCLEI": re.compile(r"(?im)^(?:Nuclei(?: Engine)?(?: Version)?[: /]+v?|\[INF\] Current nuclei version:\s*v?)(\d+(?:\.\d+){1,3})\b"),
    "HTTPX": re.compile(r"(?im)^httpx(?: version)?[: /]+v?(\d+(?:\.\d+){1,3})\b"),
    "FFUF": re.compile(r"(?im)^ffuf(?: version)?[: /]+v?(\d+(?:\.\d+){1,3})\b"),
    "SUBFINDER": re.compile(r"(?im)^subfinder(?: version)?[: /]+v?(\d+(?:\.\d+){1,3})\b"),
    "KATANA": re.compile(r"(?im)^katana(?: version)?[: /]+v?(\d+(?:\.\d+){1,3})\b"),
    "NIKTO": re.compile(r"(?im)^[-+] Nikto v(\d+(?:\.\d+){1,3})\b"),
}


def _sections(raw: str) -> dict[str, str]:
    """Parse only PenX-formatted scanner sections, never infer a scanner by prose."""
    if not isinstance(raw, str):
        return {}
    markers = [m for m in HEAD.finditer(raw) if m.group(1).strip().upper() != "PARTIAL"]
    sections: dict[str, str] = {}
    duplicates: set[str] = set()
    for index, marker in enumerate(markers):
        name = marker.group(1).strip().upper()
        end = markers[index + 1].start() if index + 1 < len(markers) else len(raw)
        if name in sections:
            duplicates.add(name)
        else:
            sections[name] = raw[marker.end():end]
    # Ambiguous duplicated sections must not establish unambiguous provenance.
    for name in duplicates:
        sections.pop(name, None)
    return sections


def scanner_coverage(data: dict) -> dict[str, str]:
    """Only typed, persisted scanner outcomes authorize a comparison verdict.

    Legacy scans without structured adapter results cannot establish that a
    negative follow-up is meaningful, even when their text looks successful.
    """
    scan_result = data.get("scan_result")
    if scan_result is None:
        return {}
    result: dict[str, str] = {}
    for adapter in scan_result.results:
        key = (adapter.display_name or adapter.scanner_id).strip().upper()
        if not key:
            continue
        if key in result:
            result[key] = "UNKNOWN"
        else:
            result[key] = adapter.status
    return result


def _observed_version(name: str, section: str) -> str | None:
    # Version is attributed ONLY if the scanner's own saved output includes
    # an explicitly matching banner. Missing versions stay null, never guessed.
    pattern = _VERSION.get(name)
    if pattern is None:
        return None
    match = pattern.search(section[:16000])
    return match.group(1) if match else None


def finding_trace(row, data: dict) -> dict:
    """Return source-backed provenance or a clear 'unattributed' verdict.

    Evidence: lines are model-authored claims, so they must match the saved raw
    scan. Matching an exact quote is not proof of CVE applicability.
    """
    summary = data.get("summary")
    raw = str(summary[2] or "") if summary else ""
    description = str(row[7] or "")[:16000] if len(row) > 7 else ""
    match = _EVIDENCE_LINE.search(description)
    quote = match.group(1).strip() if match else ""
    valid = bool(quote and evidence_in_scan(quote, raw))
    trace = {
        "scanner": None,
        "scanner_version": None,
        "scanner_status": "UNKNOWN",
        "evidence": quote if valid else "",
        "evidence_status": "scanner-quote-matched" if valid else "review-required",
        "evidence_ref": None,
        "recorded_at": str(data["history"][2]) if data.get("history") else None,
    }
    if not valid:
        return trace
    trace["evidence_ref"] = f"scan:{int(row[1])}:finding:{int(row[0])}"
    matches = [(name, body) for name, body in _sections(raw).items()
               if evidence_in_scan(quote, body)]
    if len(matches) != 1:
        # A composite quote spanning multiple tools is valid as a source
        # quotation, but is not attributable to any single scanner.
        return trace
    name, body = matches[0]
    trace["scanner"] = name
    trace["scanner_version"] = _observed_version(name, body)
    trace["scanner_status"] = scanner_coverage(data).get(name, "UNKNOWN")
    return trace


def missing_finding_status(row: dict, newer: dict) -> tuple[str, str]:
    """No automatic 'resolved': absence of an AI finding cannot prove repair."""
    source = row.get("source") or {}
    scanner = source.get("scanner")
    if not scanner or source.get("evidence_status") != "scanner-quote-matched":
        return "not_checked", "Previous finding has no attributable scanner evidence."
    status = scanner_coverage(newer).get(scanner)
    if status in {"FAILED", "PARTIAL"}:
        return "scan_failed", f"{scanner} did not complete successfully in the follow-up."
    if status != "COMPLETE":
        return "not_checked", f"{scanner} was not checked with reliable coverage in the follow-up."
    if source.get("scanner_status") != "COMPLETE":
        return "not_checked", "Previous scanner completion cannot be established."
    # A model omitting a finding is NOT negative scanner evidence. Check whether
    # the exact earlier quote persists in the same completed adapter section.
    summary = newer.get("summary")
    latest_raw = str(summary[2] or "") if summary else ""
    latest_section = _sections(latest_raw).get(scanner)
    if latest_section is None:
        return "not_checked", f"{scanner} has no unambiguous saved output section."
    if source.get("evidence") and evidence_in_scan(source["evidence"], latest_section):
        return "still_present", (
            f"{scanner} reproduced the original scanner evidence; "
            "the model omitted the finding in its follow-up report."
        )
    return "not_observed", (
        f"{scanner} completed in the follow-up; the finding was not repeated. "
        "This does not prove remediation."
    )
