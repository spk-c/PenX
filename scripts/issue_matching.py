"""Bounded, deterministic issue deduplication and secret redaction.

This module never performs requests or executes issue-supplied content.
"""
from __future__ import annotations
from difflib import SequenceMatcher
import re


def redact_text_secrets(value: str) -> str:
    """Avoid reflecting common accidentally pasted tokens in AI prompts/comments."""
    value = re.sub(
        r"(?i)\b(?:GITHUB_TOKEN|PENX_[A-Z0-9_]*(?:TOKEN|KEY|SECRET)|API_KEY)"
        r"\s*[:=]\s*[^\s,;]+",
        "[REDACTED CREDENTIAL]", value,
    )
    value = re.sub(r"\b(?:github_pat_|gh[pousr]_|sk-)[A-Za-z0-9_-]{12,}\b",
                   "[REDACTED TOKEN]", value)
    value = re.sub(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{16,}",
                   "Bearer [REDACTED]", value)
    return value


def token_terms(value: str) -> set[str]:
    common = {"with", "from", "that", "this", "when", "there", "does", "after",
              "only", "have", "using", "into", "cannot", "error", "issue", "problem",
              "penx", "should", "would", "please", "work", "works"}
    return set(re.findall(r"[a-z0-9_]{3,}", value.lower())) - common


def signature_terms(value: str) -> set[str]:
    """Extract stable code identifiers rather than generic bug-report words."""
    calls = re.findall(r"(?<!\w)([a-zA-Z_]\w{3,})\s*\(", value)
    symbols = re.findall(r"(?<!\w)([a-zA-Z_]\w*_[a-zA-Z_]\w*)(?!\w)", value)
    paths = re.findall(r"(?<!\w)(?:src/[\w/.-]+\.py|penx\.py)", value)
    # Ignore generic labels and programming constructs such as except/if.
    return {item.lower() for item in (calls + symbols + paths)[:75]
            if len(item) >= 5 and item.lower() not in
            {"except", "return", "print", "input", "str", "patch", "valueerror"}}


def find_duplicates(issue: dict, others: list[dict], *, max_body: int = 11000) -> list[dict]:
    """Find candidate duplicate defects including related, overlapping reports.

    This is conservative: a matching code symbol or linked issue alone never
    proves duplication; nothing here can close or modify a GitHub issue.
    """
    title = str(issue.get("title") or "")
    body = str(issue.get("body") or "")[:max_body]
    title_terms = token_terms(title)
    signatures = signature_terms(title + "\n" + body)
    references = set(int(x) for x in re.findall(r"(?<!\w)#(\d+)\b", body))
    found = []
    for other in others:
        number = other.get("number")
        if "pull_request" in other or not isinstance(number, int) or number == issue.get("number"):
            continue
        other_title = str(other.get("title") or "")
        other_terms = token_terms(other_title)
        ratio = SequenceMatcher(None, title.casefold(), other_title.casefold()).ratio()
        overlap = len(title_terms & other_terms) / max(1, len(title_terms | other_terms))
        other_signatures = signature_terms(
            other_title + "\n" + str(other.get("body") or "")[:max_body]
        )
        shared = signatures & other_signatures
        technical_overlap = len(shared) / max(1, min(len(signatures), len(other_signatures)))
        score = max(ratio, overlap)
        if len(shared) >= 3 and technical_overlap >= 0.68:
            score = max(score, 0.76 + min(technical_overlap, 1.0) * 0.08)
        # Referencing an older issue establishes relatedness, not identity.
        # A follow-up may report a different still-broken UI branch (#104/#87).
        explicitly_related = number in references and len(shared) >= 2
        if explicitly_related:
            score = max(score, 0.65)
        if (score >= 0.48 and
                (len(title_terms & other_terms) >= 2 or len(shared) >= 2)):
            found.append({
                "number": number, "title": other_title[:180],
                "score": round(score, 3),
                "state": str(other.get("state") or "unknown"),
                "explicitly_related": explicitly_related,
            })
    return sorted(found, key=lambda x: x["score"], reverse=True)[:5]
