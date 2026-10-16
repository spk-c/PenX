"""Pure parsing of untrusted evaluation and distilled-rule responses.

No model, database, scanner or terminal imports. Persist only after the
caller maps every candidate to one unambiguous saved-session finding.
"""
from __future__ import annotations

import re


def evaluation_groups(response_text: str) -> list[dict[str, str]]:
    """Parse Markdown-compatible EVAL groups without writing any records."""
    # External LLMs frequently bold Markdown field labels: **EVAL:** Name
    marker = re.compile(r'^\s*(?:[-*]\s+)?(?:\*\*)?(EVAL|VERDICT|CONFIDENCE|EVIDENCE|SEVERITY_CORRECT|CVE_CORRECT|SOFTWARE_CORRECT|FIX_CORRECT|NOTES):(?:\*\*)?\s*(.*)$', re.IGNORECASE)
    fields: dict[str, str] = {}
    current = None
    groups: list[dict[str, str]] = []
    for line in response_text.splitlines():
        match = marker.match(line)
        if match:
            key = match.group(1).upper()
            if key == 'EVAL':
                if fields:
                    groups.append(fields)
                fields = {}
            fields[key] = match.group(2).strip().strip('*').strip()
            current = key
        elif current and fields:
            # Multiline evidence and notes are preserved (not truncated to one line).
            fields[current] += '\n' + line
    if fields:
        groups.append(fields)


    return groups


def parse_distilled_rules(response_text: str) -> list[str]:
    """Bounded parse of untrusted RULE lines; reject oversize responses in full."""
    if len(response_text.encode("utf-8")) > 131072:
        raise ValueError("Distillation response exceeds 128 KiB")
    candidates = re.findall(r'^\s*(?:[-*]\s+)?(?:\*\*)?RULE:(?:\*\*)?\s*(.+)$',
                            response_text, re.IGNORECASE | re.MULTILINE)
    rules: list[str] = []
    for rule in candidates:
        rule = re.sub(r'\s+\(source:.*?,\s*\d{4}-\d{2}-\d{2}[^)]*\)\s*$', '', rule, flags=re.I)
        rule = rule.strip().strip('*').strip()
        if len(rule) > 1000:
            raise ValueError("Distilled rule exceeds 1000 characters")
        if len(rule) >= 10 and rule not in rules:
            if len(rules) >= 100:
                raise ValueError("Distillation response exceeds 100 unique rules")
            rules.append(rule)
    return rules
