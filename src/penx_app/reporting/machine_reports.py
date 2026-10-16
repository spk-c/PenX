"""Bounded, non-scanning JSON/SARIF exports for saved reviewed PenX sessions.

These exports do not claim that AI findings prove exploitability. They never
include full scanner raw output or secrets from the user's private .env.
Redaction is best-effort masking of the assessed host and IPv4 literals.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import tempfile

from penx_app.intelligence.source_verification import evidence_in_scan


_IPV4 = re.compile(r"(?<![\w.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![\w.])")
_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning",
                "low": "note", "info": "note"}


def _mask(value: str, target: str, enabled: bool) -> str:
    text = str(value or "")
    if not enabled:
        return text
    if target:
        text = re.sub(re.escape(target), "[TARGET REDACTED]", text, flags=re.IGNORECASE)
    def mask_address(match):
        try:
            ipaddress.IPv4Address(match.group())
        except ipaddress.AddressValueError:
            return match.group()
        return "[IPv4 REDACTED]"
    return _IPV4.sub(mask_address, text)


def _finding(row, raw_scan: str, target: str, redact: bool) -> dict:
    """Never promote legacy confirmed entries lacking scanner quote evidence."""
    desc = str(row[7] or "")
    evidence = ""
    for line in desc.splitlines():
        if line.startswith("Evidence: "):
            evidence = line[len("Evidence: "):].strip()[:2000]
            break
    matched = bool(evidence and evidence_in_scan(evidence, raw_scan))
    confidence = str(row[4] or "possible").lower()
    if not matched and confidence == "confirmed":
        confidence = "possible"
    name = str(row[2] or "Unnamed finding")
    return {
        "id": int(row[0]),
        "rule": "PENX-" + hashlib.sha256(name.lower().encode("utf-8")).hexdigest()[:12],
        "name": _mask(name, target, redact),
        "severity": str(row[3] or "unknown").lower(),
        "confidence": confidence,
        "status": "review-required" if not matched else "scanner-quote-matched",
        "port": str(row[5] or "")[:40],
        "service": _mask(str(row[6] or "")[:120], target, redact),
        "description": _mask(desc[:16000], target, redact),
        "evidence": _mask(evidence, target, redact) if matched else "",
        "evidence_ref": f"scan:{int(row[1])}:finding:{int(row[0])}" if matched else None,
    }


def report_payload(data: dict, *, redact: bool = False) -> dict:
    from penx_app.reporting.report_view import ReportView
    history = data.get("history")
    summary = data.get("summary")
    if not history or not summary:
        raise ValueError("Cannot export a missing or incomplete saved assessment")
    target = str(history[1] or "")
    raw = str(summary[2] or "")
    findings = [_finding(row, raw, target, redact)
                for row in ReportView.from_session(data).active_findings]
    return {
        "schema": "penx-assessment-v1",
        "session": int(history[0]),
        "target": _mask(target, target, redact),
        "scan_date": str(history[2]),
        "risk": str(summary[4] or "UNKNOWN").upper(),
        "findings": findings,
        "limitations": [
            "AI conclusions are hypotheses until independently verified.",
            "Scanner-quote-matched means an exact quote exists; not proof of exploitability.",
            "Raw scanner output is intentionally omitted from machine-readable exports.",
            "Redaction masks the assessed target and IPv4 literals only; review before sharing."
        ],
    }


def sarif_payload(data: dict, *, redact: bool = False) -> dict:
    report = report_payload(data, redact=redact)
    rules = {}
    results = []
    for finding in report["findings"]:
        if finding["confidence"] == "recommendation":
            continue
        rule_id = finding["rule"]
        rules.setdefault(rule_id, {
            "id": rule_id,
            "shortDescription": {"text": finding["name"][:200]},
            "properties": {"tags": ["security", "penx", "requires-human-review"]},
        })
        results.append({
            "ruleId": rule_id,
            "level": _SARIF_LEVEL.get(finding["severity"], "note"),
            "message": {"text": (finding["name"] + ": " + finding["description"])[:8000]},
            "properties": {
                "penxFindingId": finding["id"],
                "confidence": finding["confidence"],
                "evidenceStatus": finding["status"],
                "evidenceRef": finding["evidence_ref"],
                "session": report["session"],
                "scope": report["target"],
                "port": finding["port"],
            },
        })
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {
                "name": "PenX",
                "informationUri": "https://gitlab.com/SLP-DEV1/PenX",
                "rules": list(rules.values()),
            }},
            "results": results,
            "properties": {"limitations": report["limitations"]},
        }],
    }


def write_machine_report(data: dict, output_dir: str | Path, *, fmt: str = "json",
                         redact: bool = False) -> Path:
    if fmt not in ("json", "sarif"):
        raise ValueError("Only JSON or SARIF exports are supported")
    report = report_payload(data, redact=redact) if fmt == "json" else sarif_payload(data, redact=redact)
    root = Path(output_dir)
    root.mkdir(parents=True, exist_ok=True)
    session = int(data["history"][0])
    if session < 1:
        raise ValueError("Invalid saved session")
    basename = f"penx_SL{session}_{'redacted_' if redact else ''}assessment"
    contents = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    tmp = None
    try:
        with tempfile.NamedTemporaryFile("w", dir=root, prefix=".penx-report-", suffix=".tmp",
                                         delete=False, encoding="utf-8") as stream:
            tmp = Path(stream.name)
            stream.write(contents)
        # Refuse to overwrite prior report files (including races).
        for n in range(101):
            name = f"{basename}{('_' + str(n)) if n else ''}.{fmt}"
            target = root / name
            try:
                os.link(tmp, target)
                return target
            except FileExistsError:
                continue
        raise FileExistsError("Too many existing reports; no saved file was overwritten")
    finally:
        if tmp and tmp.exists():
            tmp.unlink()


def export_cli(argv: list[str]) -> int:
    """Export an existing session without invoking the LLM or any scanner."""
    parser = argparse.ArgumentParser(prog="PenX --export-session")
    parser.add_argument("session", type=int)
    parser.add_argument("--format", choices=("json", "sarif"), required=True)
    parser.add_argument("--redact", action="store_true")
    parser.add_argument("--output-dir", default=None)
    args = parser.parse_args(argv)
    if args.session < 1:
        parser.error("session ID must be a positive integer")
    from penx_app.app_paths import APP_ROOT
    from penx_app.reporting.export import fetch_session
    try:
        data = fetch_session(args.session)
        if not data.get("history"):
            print(f"[ERROR] Session {args.session} does not exist")
            return 1
        out = write_machine_report(data, args.output_dir or APP_ROOT / "reports",
                                   fmt=args.format, redact=args.redact)
    except (OSError, ValueError, TypeError) as exc:
        print(f"[ERROR] Could not export session: {exc}")
        return 1
    print(f"[OK] Saved {args.format.upper()} assessment: {out}")
    return 0
