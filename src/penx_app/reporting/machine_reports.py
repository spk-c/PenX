"""Bounded, non-scanning JSON/SARIF exports for saved reviewed PenX sessions.

These exports do not claim that AI findings prove exploitability. They never
include full scanner raw output or secrets from the user's private .env.
Redaction is best-effort masking of the assessed host and IP literals.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

from penx_app.file_output import publish_unique
from penx_app.domain.finding_identity import finding_fingerprint
from penx_app.intelligence.source_verification import evidence_in_scan


_IPV4 = re.compile(r"(?<![\w.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![\w.])")
# Recognize IPv6 addresses including compressed, mapped and scoped forms.
# Only a successfully parsed IPv6Address is masked; ordinary colon-delimited
# text and URLs without a literal IPv6 address remain unchanged.
_IPV6 = re.compile(
    r"(?<![A-Za-z0-9_.:])(?:[0-9A-Fa-f]{0,4}:){2,7}"
    r"(?:[0-9A-Fa-f]{0,4}|(?:[0-9]{1,3}\.){3}[0-9]{1,3})"
    r"(?:%[A-Za-z0-9_.-]+)?(?![A-Za-z0-9_.:])"
)
_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning",
                "low": "note", "info": "note"}


def _mask(value: str, target: str, enabled: bool) -> str:
    text = str(value or "")
    if not enabled:
        return text
    if target:
        text = re.sub(re.escape(target), "[TARGET REDACTED]", text, flags=re.IGNORECASE)
        # A session target may be a full URL. Its host also appears in scanner
        # findings independently (without scheme, port or path).
        try:
            ipaddress.ip_address(target.strip("[]"))
        except ValueError:
            try:
                parsed = urlsplit(target if "://" in target else "//" + target)
                host = parsed.hostname
            except ValueError:
                host = None  # Historical malformed targets must not crash exports.
            if host:
                try:
                    ipaddress.ip_address(host)
                except ValueError:
                    text = re.sub(
                        r"(?<![A-Za-z0-9_.-])" + re.escape(host)
                        + r"(?![A-Za-z0-9_.-])",
                        "[TARGET REDACTED]", text, flags=re.IGNORECASE,
                    )
    def mask_address(match):
        try:
            ipaddress.IPv4Address(match.group())
        except ipaddress.AddressValueError:
            return match.group()
        return "[IPv4 REDACTED]"

    def mask_ipv6(match):
        try:
            ipaddress.IPv6Address(match.group())
        except ipaddress.AddressValueError:
            return match.group()
        return "[IPv6 REDACTED]"

    text = _IPV6.sub(mask_ipv6, text)
    return _IPV4.sub(mask_address, text)


def _finding(row, raw_scan: str, target: str, redact: bool, *, session: dict | None = None) -> dict:
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
    # Attribution is separately verified against a saved scanner section.
    # Model prose and guesses must never fill a missing scanner version.
    from penx_app.reporting.finding_trace import finding_trace
    trace = finding_trace(row, session) if session is not None else {}
    return {
        "fingerprint": finding_fingerprint(name, row[5], row[6], target=target.strip().lower().rstrip('/')),
        "raw_artifact": trace.get("raw_artifact"),
        "artifact_status": trace.get("artifact_status", "not-retained"),
        "raw_evidence": _mask(trace.get("raw_evidence") or "", target, redact),
        "scanner": trace.get("scanner"),
        "scanner_version": trace.get("scanner_version"),
        "scanner_status": trace.get("scanner_status", "UNKNOWN"),
        "evidence_recorded_at": trace.get("recorded_at"),
        "id": int(row[0]),
        "rule": "PENX-" + hashlib.sha256(name.lower().encode("utf-8")).hexdigest()[:12],
        "name": _mask(name, target, redact),
        "severity": str(row[3] or "unknown").lower(),
        "confidence": confidence,
        "status": "review-required" if not matched else "scanner-quote-matched",
        "port": _mask(str(row[5] or "")[:40], target, redact),
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
    from penx_app.intelligence.php2shell_audit import assess_php2shell
    php2shell = assess_php2shell(raw)
    findings = [_finding(row, raw, target, redact, session=data)
                for row in ReportView.from_session(data).active_findings]
    return {
        "schema": "penx-assessment-v1",
        "session": int(history[0]),
        "target": _mask(target, target, redact),
        "scan_date": str(history[2]),
        "risk": str(summary[4] or "UNKNOWN").upper(),
        "findings": findings,
        "php2shell": php2shell,
        "limitations": [
            "AI conclusions are hypotheses until independently verified.",
            "Scanner-quote-matched means an exact quote exists; not proof of exploitability.",
            "Full raw scanner output is omitted; bounded verified excerpts may be included.",
            "Redaction masks the assessed target and IPv4/IPv6 literals only; review before sharing."
        ],
    }


def sarif_payload(data: dict, *, redact: bool = False) -> dict:
    report = report_payload(data, redact=redact)
    return sarif_from_report(report)


def sarif_from_report(report: dict) -> dict:
    """Shared SARIF formatting for saved assessments and headless captures."""
    rules: dict[str, dict] = {}
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
            "partialFingerprints": {"penxFinding/v1": finding["fingerprint"]},
            "ruleId": rule_id,
            "level": _SARIF_LEVEL.get(finding["severity"], "note"),
            "message": {"text": (finding["name"] + ": " + finding["description"])[:8000]},
            "properties": {
                "penxFindingId": finding["id"],
                "findingFingerprint": finding["fingerprint"],
                "rawArtifact": finding["raw_artifact"],
                "artifactStatus": finding["artifact_status"],
                "confidence": finding["confidence"],
                "evidenceStatus": finding["status"],
                "evidenceRef": finding["evidence_ref"],
                "scanner": finding["scanner"],
                "scannerVersion": finding["scanner_version"],
                "scannerStatus": finding["scanner_status"],
                "evidenceRecordedAt": finding["evidence_recorded_at"],
                "session": report["session"],
                "scope": report["target"],
                "port": finding["port"],
            },
        })
    payload: dict = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {
                "name": "PenX",
                "informationUri": "https://github.com/spk-c/PenX",
                "rules": list(rules.values()),
            }},
            "results": results,
            "properties": {
                "php2shell": report["php2shell"],
                "limitations": report["limitations"],
            },
        }],
    }
    if report.get('schema') == 'penx-scan-v1':
        run = payload['runs'][0]
        run['properties'].update({
            'coverage': report['coverage'], 'profile': report.get('profile'),
            'scannerConfiguration': report.get('scanner_configuration', []),
            'dependencies': report.get('dependencies', []),
            'policy': report.get('policy'), 'exitCode': report.get('exit_code'),
            'findingsTruncated': report.get('findings_truncated', False),
        })
        complete = report['coverage']['status'] == 'COMPLETE' and not report.get('findings_truncated')
        run['invocations'] = [{
            'executionSuccessful': bool(complete),
            'toolExecutionNotifications': [
                {'level': 'error' if row['status'] == 'FAILED' else 'warning',
                 'message': {'text': row['id'] + ': ' + (row.get('diagnostics') or row['status'])}}
                for row in report.get('adapters', []) if row['status'] != 'COMPLETE'
            ],
        }]
    return payload


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
    # The shared publisher fsyncs the completed staging file before linking
    # an exclusive final name. The old local implementation linked an
    # unsynchronized temporary file, risking incomplete recovery after a
    # storage interruption. Preserve existing filenames and no-overwrite.
    return publish_unique(root, basename, "." + fmt, contents)


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
