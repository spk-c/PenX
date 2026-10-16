"""Evidence-aware budget for untrusted scanner text supplied to local LLMs.

Raw evidence stays unchanged for archival analysis and CVE extraction. Only
the model-facing text is shortened. Sections and omitted counts are explicit.
"""
from __future__ import annotations

import re

IMPORTANT = re.compile(
    r"(?i)(?:\bopen\b|\b(?:tcp|udp)/\d+\b|\bCVE-\d{4}-\d{4,}\b|"
    r"\bcpe:|\bversion\b|\bservice\b|\bserver:|\bwordpress\b|"
    r"\bnikto\b|\bsecurity\b|\bvulnerab|\bERROR\b|\bSSL\b|\bTLS\b|"
    r"\bHTTP/|\bwhatweb\b|\bport\b|\bexposed\b)"
)
HEADER = re.compile(r"^\s*\[\s*[A-Z][A-Z0-9_ /-]{2,70}\s*\]\s*$")


def bound_scan_text(raw: str, limit: int = 60000) -> str:
    """Select evidence across the whole scan, not just its first busy section.

    Prefer beginning/end diagnostics, every scanner heading and high-signal
    lines sampled from both ends. The full raw evidence remains untouched.
    """
    raw = str(raw or "")
    limit = max(2048, min(int(limit), 500_000))
    if len(raw) <= limit:
        return raw

    lines = raw.splitlines()
    # Keep room for a deterministic explanation of what was lost.
    available = limit - 350
    chosen = {}
    used = 0

    def add(index: int) -> None:
        nonlocal used
        if index in chosen:
            return
        value = lines[index][:1200]
        if used + len(value) + 1 > available:
            return
        chosen[index] = value
        used += len(value) + 1

    # Preserve both ends even if one scanner emits a very large body.
    for i in list(range(min(8, len(lines)))) + list(range(max(0, len(lines) - 8), len(lines))):
        add(i)
    # Section headers make it possible to attribute selected observations.
    for i, line in enumerate(lines):
        if HEADER.fullmatch(line[:100]):
            add(i)
    relevant = [i for i, line in enumerate(lines)
                if IMPORTANT.search(line[:1600]) and i not in chosen]
    # An overlong opening scanner must never consume every slot: alternate
    # between early and late findings.
    left, right = 0, len(relevant) - 1
    while left <= right:
        add(relevant[left])
        if left != right:
            add(relevant[right])
        left += 1
        right -= 1
    # Fill residual space with context, still bound the number of characters.
    for i in range(len(lines)):
        add(i)

    omitted = len(lines) - len(chosen)
    prefix = (f"[TRUNCATED SCAN EVIDENCE: {len(raw)} original characters, "
              f"{omitted} line(s) omitted; original evidence retained. "
              "Absence of a fact below does NOT establish its absence on target.]\n")
    return prefix + "\n".join(chosen[i] for i in sorted(chosen))
