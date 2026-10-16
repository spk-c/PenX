"""Authoritative scan outcome projection and conservative legacy reader.

The canonical scan path uses typed ScanResult/ReconText metadata. Parsing
historical plain-string evidence remains a bounded compatibility boundary.
No scanner processes, network calls, terminal I/O or storage imports here.
"""
from __future__ import annotations

import re

from penx_app.domain.scan_models import (
    ReconText, ScanResult, ScannerResult, ScannerOutput,
)


def format_recon_for_llm(results: dict | ScanResult) -> str:
    # Active scanner execution transports typed results to this boundary;
    # the text is derived, not a source for trusted statuses.
    if isinstance(results, ScanResult):
        results = {
            result.display_name or result.scanner_id: ScannerOutput(
                result.text, status=result.status, evidence=result.evidence,
                scanner_id=result.scanner_id,
                duration_seconds=result.duration_seconds,
                exit_code=result.exit_code,
                diagnostics=result.diagnostics,
                evidence_records=result.evidence_records,
            )
            for result in results.results
        }
    sections = []
    for tool, data in results.items():
        # Metadata is authored by the adapter, never copied from its remote output.
        # Legacy plain-string test fixtures and callers keep the old formatting.
        marker = (f"[PENX ADAPTER STATUS: {data.status}; "
                  f"EVIDENCE: {'YES' if data.evidence else 'NO'}]\n"
                  if isinstance(data, ScannerOutput) else "")
        sections.append(
            f"\n{'='*50}\n[ {tool.upper()} OUTPUT ]\n{'='*50}\n"
            f"{marker}{str(data).strip()}\n")
    text = ''.join(sections)
    # Plain-string callers retain the conservative legacy reader.
    if all(isinstance(data, ScannerOutput) for data in results.values()):
        return ReconText(text, ScanResult(tuple(
            ScannerResult(data.scanner_id or tool, str(data), data.status,
                          data.evidence, tool, data.duration_seconds,
                          data.exit_code, data.diagnostics,
                          data.evidence_records)
            for tool, data in results.items())))
    return text


def recon_has_evidence(raw_scan: str, *, passive_only: bool = False) -> bool:
    """Reject collections containing *only* scanner/provider error diagnostics.

    A partial scan is allowed only if at least one independent adapter produced
    usable evidence. This is a safeguard, not a vulnerability confirmation.
    """
    if not passive_only and isinstance(raw_scan, ScanResult):
        return raw_scan.has_evidence
    if not passive_only and isinstance(raw_scan, ReconText):
        return raw_scan.result.has_evidence
    if not isinstance(raw_scan, str) or not raw_scan.strip():
        return False

    def usable(body: str, *, selected_section: bool = False) -> bool:
        value = body.strip()
        if not value:
            return False
        # Status metadata is only meaningful inside the formatted selected-tool
        # boundary, never as standalone raw data (which may be untrusted).
        status = re.match(
            r'^\[PENX ADAPTER STATUS: (COMPLETE|PARTIAL|FAILED); '
            r'EVIDENCE: (YES|NO)\](?:\r?\n|$)', value)
        if status:
            return (status.group(1) != "FAILED" and status.group(2) == "YES"
                    if selected_section else False)
        # Native adapters include banners even when every request failed.
        # Require their actual result records, not just a non-error first line.
        if re.match(r'^\[https?://[^\n]+ headers ', value, re.I):
            return bool(re.search(r'(?im)^HTTP [1-5]\d{2} -> https?://', value))
        if value.startswith('[Windows Python fingerprint fallback'):
            return bool(re.search(r'(?im)^https?://\S+ -> HTTP [1-5]\d{2}\b', value))
        if value.startswith('[Native Python DNS queries]'):
            return any(
                line.strip() and not line.strip().startswith(('[', '(!)', '(no record)'))
                for line in value.splitlines()
            )
        if value.startswith(("[!", "[EXIT CODE", "[ERROR]", "Traceback ")):
            return False
        if re.match(r"(?i)^(?:unavailable|not installed|no (?:results?|records?|entries|data)|error:|failed:)", value):
            return False
        return True

    if passive_only:
        # The introductory banner and "provider unavailable" warnings do not
        # constitute successfully collected passive evidence.
        for marker in ("[WHOIS REGISTRY]", "[DNS VIA RESOLVER]", "[CERTIFICATE TRANSPARENCY]",
                       "[RDAP]", "[SHODAN INTERNETDB RECORD]", "[CENSYS HISTORICAL INDEX]"):
            for part in raw_scan.split(marker + "\n")[1:]:
                body = part.split("\n\n[", 1)[0].strip()
                if marker == "[DNS VIA RESOLVER]":
                    # Strip each value before checking diagnostics. A greedy
                    # whitespace regex can backtrack past a negative lookahead.
                    values = re.findall(r"(?im)^(?:A|AAAA|MX|NS|TXT):([^\r\n]*)", body)
                    if any(usable(value) for value in values):
                        return True
                elif usable(body) and not body.lower().startswith("no structured response"):
                    return True
        return False

    # Tool-selected output is separated into individually labelled blocks.
    chunks = re.split(r"\n={20,}\n\[ [^\]\n]+ OUTPUT \]\n={20,}\n", raw_scan)
    if len(chunks) == 1:
        return usable(raw_scan)  # Legacy single-source callers and offline fixtures.
    return any(usable(block, selected_section=True) for block in chunks[1:])
