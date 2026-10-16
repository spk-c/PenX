#!/usr/bin/env python3
"""
PenX - parsers.py
Extract structured data (vulns, recommendations, exploits, risk, summary)
from AI response text. Pure functions — no side effects, no DB, no API calls.
"""

import re


def _clean(line: str) -> str:
    return re.sub(r'^[-*]\s+', '', re.sub(r'\*+', '', line).strip()).strip()


def parse_vulnerabilities(response: str) -> list:
    """
    Parse VULN: lines from AI response into dicts.
    Returns list of vulnerability dicts ready for db.save_vulnerability()
    """
    vulns = []
    lines = response.splitlines()

    i = 0
    while i < len(lines):
        line = _clean(lines[i])
        if line.startswith("VULN:"):
            vuln = {
                "vuln_name":   "",
                "severity":    "medium",
                "confidence":  "possible",
                "port":        "",
                "service":     "",
                "description": "",
                "fix":         ""
            }

            parts = line.split("|")
            for part in parts:
                part = part.strip()
                if part.startswith("VULN:"):
                    vuln["vuln_name"] = part.replace("VULN:", "").strip()
                elif part.startswith("SEVERITY:"):
                    vuln["severity"] = part.replace("SEVERITY:", "").strip().lower()
                elif part.startswith("CONFIDENCE:"):
                    vuln["confidence"] = part.replace("CONFIDENCE:", "").strip().lower()
                elif part.startswith("PORT:"):
                    vuln["port"] = part.replace("PORT:", "").strip()
                elif part.startswith("SERVICE:"):
                    vuln["service"] = part.replace("SERVICE:", "").strip()

            if vuln["confidence"] not in ("confirmed", "likely", "possible"):
                vuln["confidence"] = "possible"
            if vuln["severity"] not in ("critical", "high", "medium", "low", "info"):
                vuln["severity"] = "unknown"

            j = i + 1
            while j < len(lines) and j <= i + 6:
                next_line = _clean(lines[j])
                if next_line.startswith(("VULN:", "REC:", "EXPLOIT:", "RISK_LEVEL:", "SUMMARY:")):
                    break
                if next_line.startswith("EVIDENCE:"):
                    vuln["evidence"] = next_line.replace("EVIDENCE:", "").strip()
                elif next_line.startswith("DESC:"):
                    vuln["description"] = next_line.replace("DESC:", "").strip()
                elif next_line.startswith("FIX:"):
                    vuln["fix"] = next_line.replace("FIX:", "").strip()
                j += 1

            if vuln["vuln_name"]:
                if vuln.get("evidence"):
                    # Existing SQLite schema has no dedicated evidence column.
                    # Preserve scan citations in the stored description and report.
                    vuln["description"] += "\nEvidence: " + vuln["evidence"]
                vulns.append(vuln)

        i += 1

    return vulns


def parse_recommendations(response: str) -> list:
    """
    Parse REC: lines from AI response into dicts.
    Stored as vulns with severity='info' and confidence='recommendation'.
    """
    recs = []
    lines = response.splitlines()

    i = 0
    while i < len(lines):
        line = _clean(lines[i])
        if line.startswith("REC:"):
            rec = {
                "vuln_name":   line.replace("REC:", "").strip(),
                "severity":    "info",
                "confidence":  "recommendation",
                "port":        "",
                "service":     "",
                "description": "",
                "fix":         ""
            }

            j = i + 1
            while j < len(lines) and j <= i + 3:
                next_line = _clean(lines[j])
                if next_line.startswith(("VULN:", "REC:", "EXPLOIT:", "RISK_LEVEL:", "SUMMARY:")):
                    break
                if next_line.startswith("DESC:"):
                    rec["description"] = next_line.replace("DESC:", "").strip()
                j += 1

            if rec["vuln_name"]:
                recs.append(rec)

        i += 1

    return recs


def parse_exploits(response: str) -> list:
    """
    Parse EXPLOIT: lines from AI response into dicts.
    Returns list of exploit dicts ready for db.save_exploit()
    """
    exploits = []
    lines = response.splitlines()

    i = 0
    while i < len(lines):
        line = _clean(lines[i])
        if line.startswith("EXPLOIT:"):
            exploit = {
                "exploit_name": "",
                "tool_used":    "",
                "payload":      "",
                "result":       "unknown",
                "notes":        ""
            }

            parts = line.split("|")
            for part in parts:
                part = part.strip()
                if part.startswith("EXPLOIT:"):
                    exploit["exploit_name"] = part.replace("EXPLOIT:", "").strip()
                elif part.startswith("TOOL:"):
                    exploit["tool_used"] = part.replace("TOOL:", "").strip()
                elif part.startswith("PAYLOAD:"):
                    exploit["payload"] = part.replace("PAYLOAD:", "").strip()

            j = i + 1
            while j < len(lines) and j <= i + 4:
                next_line = _clean(lines[j])
                if next_line.startswith(("VULN:", "EXPLOIT:", "RISK_LEVEL:", "SUMMARY:")):
                    break
                if next_line.startswith("RESULT:"):
                    exploit["result"] = next_line.replace("RESULT:", "").strip()
                elif next_line.startswith("NOTES:"):
                    exploit["notes"] = next_line.replace("NOTES:", "").strip()
                j += 1

            if exploit["exploit_name"]:
                exploits.append(exploit)

        i += 1

    return exploits


def parse_risk_level(response: str) -> str:
    """Extract RISK_LEVEL from AI response."""
    match = re.search(r'RISK_LEVEL:\s*(CRITICAL|HIGH|MEDIUM|LOW)', response, re.IGNORECASE)
    return match.group(1).upper() if match else "UNKNOWN"


def parse_summary(response: str) -> str:
    match = re.search(r'(?im)^SUMMARY:\s*(.*(?:\n(?![A-Z_]+:).+)*)', response)
    return match.group(1).strip() if match else ""
