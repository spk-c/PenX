"""Conservative adapter coverage derived from stored, selected scanner sections.

PARTIAL describes collection completeness, not vulnerability risk.
"""
from __future__ import annotations

import re
from penx_app.domain.scan_models import ReconText, ScanResult

HEAD = re.compile(r"(?m)^\[[ \t]*([A-Za-z0-9_ /(),.-]+?)[ \t]+OUTPUT[ \t]*\]\r?$")
# Trusted adapter metadata appears immediately after the formatted section header.
# Legacy saved reports without it continue through conservative diagnostics.
ADAPTER_STATUS = re.compile(
    r"^\[PENX ADAPTER STATUS: (COMPLETE|PARTIAL|FAILED); EVIDENCE: (YES|NO)\](?:\r?\n|$)"
)
FAIL = re.compile(
    r"(?im)(?:^\s*\[EXIT CODE [+-]?[1-9]\d*\]|^\s*\[!\]|"
    r"^\s*(?:[-+]\s*)?ERROR:\s|^\s*\+\s*\[FAIL\]|Required module not found|"
    r"^\s*\[!] Timed out|^\s*\[PARTIAL OUTPUT\]|"
    r"^\s*\[!] Executable not found|^\s*\[!] Could not start|"
    r"error limit\s*\(\d+\)\s*reached|scan terminated:\s*\d+\s+errors|ssl connect failed)"
)


def coverage(raw_scan: str, *, passive_only: bool = False) -> dict:
    if passive_only:
        return {"status": "PASSIVE", "completed": [], "failed": [],
                "note": "Passive source collection; active scanners were not requested."}
    if isinstance(raw_scan, ScanResult):
        return raw_scan.coverage()
    if isinstance(raw_scan, ReconText):
        return raw_scan.result.coverage()
    markers = [m for m in HEAD.finditer(raw_scan or "")
               if m.group(1).strip().upper() != "PARTIAL"]
    completed, failed = [], []
    for index, marker in enumerate(markers):
        name = marker.group(1).strip().upper()
        end = markers[index + 1].start() if index + 1 < len(markers) else len(raw_scan)
        content = raw_scan[marker.end():end].strip()
        # format_recon_for_llm separates the heading and body with an equals
        # rule; remove only that known formatting before reading the status.
        content = re.sub(r"^={20,}\r?\n", "", content).lstrip()
        adapter = ADAPTER_STATUS.match(content)
        if adapter:
            # PARTIAL is intentionally incomplete coverage even when a working
            # fallback produced some independent usable evidence.
            if adapter.group(1) == "COMPLETE":
                completed.append(name)
            else:
                failed.append(name)
        elif not content or FAIL.search(content) or content.startswith("[Windows Python fingerprint fallback"):
            failed.append(name)
        else:
            completed.append(name)
    state = "PARTIAL" if failed else ("COMPLETE" if completed else "UNKNOWN")
    return {"status": state, "completed": completed, "failed": failed,
            "note": ("Some selected scanners failed; absence of findings is inconclusive."
                     if failed else "Only selected scanners are covered; unselected scanners were not run.")}
