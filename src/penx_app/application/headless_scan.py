"""Noninteractive authorized collection with deterministic reports and CI policy."""
from __future__ import annotations

import argparse
from dataclasses import asdict, replace
from datetime import datetime, timezone
import json
import re

from penx_app.application.preflight import _build_plan, build_preflight, format_report
from penx_app.application.scan_planner import run_plan
from penx_app.cli.scanner_cancellation import scanner_cancellation
from penx_app.domain.finding_identity import finding_fingerprint
from penx_app.domain.scan_diagnostics import PlanSummary
from penx_app.domain.scan_models import ScanResult
from penx_app.file_output import publish_unique
from penx_app.reporting.machine_reports import _mask, sarif_from_report
from penx_app.scanners.scanner_targets import normalize_host

SEVERITIES = {'info': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
_TEMPLATE = re.compile(r'^TEMPLATE ([^|]{1,400}) \| (info|low|medium|high|critical) \| (.{1,500}) \| (.{1,1000})$')


def scan_report(plan, result: ScanResult, *, redact: bool = False) -> dict:
    """Report explicit scanner observations with conservative severity rules.

    Raw banners, errors and inventory are never interpreted as vulnerabilities.
    A template match still requires independent human applicability review.
    """
    findings: list[dict] = []
    seen_nuclei: dict[str, int] = {}
    findings_truncated = False
    for adapter in result.results:
        if adapter.scanner_id != 'nuclei' or not adapter.evidence or adapter.status == 'FAILED':
            continue
        findings_truncated = findings_truncated or len(adapter.text) > 1_048_576
        for line in adapter.text[:1_048_576].splitlines():
            match = _TEMPLATE.fullmatch(line)
            if not match:
                continue
            template, severity, name, location = (part.strip() for part in match.groups())
            fingerprint = finding_fingerprint(template, location, 'nuclei', target=plan.target)
            existing = seen_nuclei.get(fingerprint)
            if existing is not None and SEVERITIES[severity] <= SEVERITIES[findings[existing]['severity']]:
                continue
            if existing is None and len(findings) >= 1000:
                findings_truncated = True
                continue
            finding = {
                'id': existing + 1 if existing is not None else len(findings) + 1,
                'rule': _mask('PENX-NUCLEI-' + template, plan.target, redact),
                'fingerprint': fingerprint, 'name': _mask(name, plan.target, redact),
                'description': 'Nuclei template match; applicability requires independent review.',
                'severity': severity, 'confidence': 'possible', 'status': 'scanner-quote-matched',
                'port': '', 'service': 'http', 'scanner': 'nuclei', 'scanner_version': None,
                'scanner_status': adapter.status, 'evidence_recorded_at': None,
                'evidence': _mask(line, plan.target, redact),
                'raw_evidence': _mask(line, plan.target, redact),
                'evidence_ref': fingerprint,
                'raw_artifact': asdict(adapter.raw_artifact) if adapter.raw_artifact else None,
                'artifact_status': 'stored-reference-not-revalidated' if adapter.raw_artifact else 'not-retained',
            }
            if existing is None:
                seen_nuclei[fingerprint] = len(findings)
                findings.append(finding)
            else:
                findings[existing] = finding
    from penx_app.application.scanner_observations import observations
    seen = {item['fingerprint'] for item in findings}
    for adapter in result.results:
        if (adapter.status == 'COMPLETE' and adapter.evidence
                and adapter.scanner_id in ('tls', 'http_headers', 'nmap', 'nikto')
                and len(adapter.text) > 1_048_576):
            findings_truncated = True
        for rule, name, severity, quote, location in observations(adapter):
            fingerprint = finding_fingerprint(rule, location, adapter.scanner_id, target=plan.target)
            if fingerprint in seen:
                continue
            if len(findings) >= 1000:
                findings_truncated = True
                continue
            seen.add(fingerprint)
            findings.append({
                'id': len(findings) + 1, 'rule': 'PENX-' + rule, 'fingerprint': fingerprint,
                'name': name, 'description': 'Scanner observation; independent applicability review required.',
                'severity': severity, 'confidence': 'possible', 'status': 'scanner-quote-matched',
                'port': location.split('/')[0] if adapter.scanner_id == 'nmap' else '',
                'service': _mask(location, plan.target, redact), 'scanner': adapter.scanner_id, 'scanner_version': None,
                'scanner_status': adapter.status, 'evidence_recorded_at': None,
                'evidence': _mask(quote, plan.target, redact), 'raw_evidence': _mask(quote, plan.target, redact),
                'evidence_ref': fingerprint,
                'raw_artifact': asdict(adapter.raw_artifact) if adapter.raw_artifact else None,
                'artifact_status': 'stored-reference-not-revalidated' if adapter.raw_artifact else 'not-retained',
            })
    return {
        'schema': 'penx-scan-v1', 'session': None,
        'target': _mask(plan.target, plan.target, redact),
        'scan_date': datetime.now(timezone.utc).isoformat(),
        'profile': asdict(result.plan_summary) if result.plan_summary else None,
        'scanner_configuration': [item.to_dict() for item in result.scanner_configuration],
        'dependencies': [list(edge) for edge in plan.dependencies],
        'coverage': result.coverage(),
        'adapters': [{'id': row.scanner_id, 'status': row.status, 'evidence': row.evidence,
                      'diagnostics': _mask(row.diagnostics, plan.target, redact),
                      'raw_artifact': asdict(row.raw_artifact) if row.raw_artifact else None}
                     for row in result.results],
        'findings': findings, 'findings_truncated': findings_truncated, 'php2shell': None,
        'limitations': [
            'Headless collection runs without AI and creates no saved assessment session.',
            'Deterministic rules cover Nuclei, selected HTTP/TLS checks and Nmap/Nikto observations; other adapters supply coverage only.',
            'No matches does not establish absence of vulnerabilities.',
            'Hashes attest integrity against trusted references, not exploitability.',
        ],
    }


def policy_exit(result: ScanResult, findings: list[dict], threshold: str | None,
                *, findings_truncated: bool = False) -> int:
    """Error > incomplete coverage > finding policy > successful collection."""
    if any(row.status == 'FAILED' for row in result.results):
        return 4
    if findings_truncated or not result.results or any(row.status != 'COMPLETE' for row in result.results):
        return 5
    if threshold and any(SEVERITIES.get(row['severity'], -1) >= SEVERITIES[threshold]
                         for row in findings):
        return 3
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog='penx scan', description=__doc__)
    parser.add_argument('--target', required=True)
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument('--profile')
    selection.add_argument('--scanners', help='Explicit comma-separated registry keys')
    selection.add_argument('--profile-file', help='Validated local profile JSON (no embedded authorization)')
    parser.add_argument('--authorized', action='store_true', help='Confirm authorization for this exact target')
    parser.add_argument('--consent', action='store_true', help='Authorize consent-gated active web checks')
    parser.add_argument('--output', default='./reports')
    parser.add_argument('--format', choices=('json', 'sarif', 'both'), default='json')
    parser.add_argument('--redact', action='store_true')
    parser.add_argument('--fail-on', choices=tuple(SEVERITIES))
    parser.add_argument('--max-parallelism', type=int)
    parser.add_argument('--budget', type=int)
    parser.add_argument('--dispatch-interval', type=float)
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--raw-artifacts', help='Opt-in private raw capture directory')
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    dispatched = False
    try:
        target = args.target.strip()
        normalize_host(target)  # Pure validation before availability probes or adapters.
        if args.profile_file:
            from penx_app.application.profile_documents import load_profile
            plan = load_profile(args.profile_file).to_plan(target, active_consent=args.consent)
        else:
            plan = _build_plan(target, profile=args.profile, scanners=args.scanners, consent=args.consent)
        plan = replace(plan, max_parallelism=args.max_parallelism if args.max_parallelism is not None else plan.max_parallelism,
                       global_budget_seconds=args.budget if args.budget is not None else plan.global_budget_seconds,
                       dispatch_interval_seconds=args.dispatch_interval if args.dispatch_interval is not None else plan.dispatch_interval_seconds)
        from penx_app.domain.scan_plan import assert_valid_plan
        assert_valid_plan(plan)
        if plan.max_parallelism > 8 or (plan.global_budget_seconds is not None and plan.global_budget_seconds > 3600):
            raise ValueError('Headless limits: at most 8 workers and a 3600-second global budget')
        if args.dry_run:
            preflight = build_preflight(plan)
            print(format_report(preflight))
            return 0 if preflight.available else 4
        if not args.authorized:
            raise ValueError('Pass --authorized only for targets you own or have explicit permission to assess.')
        if plan.passive_only and plan.max_parallelism != 1:
            raise ValueError('Passive providers run sequentially; use max-parallelism 1.')
        dispatched = True
        if plan.passive_only:
            from penx_app.application.passive_execution import run_passive_plan
            with scanner_cancellation() as event:
                result = run_passive_plan(plan, cancel_event=event)
        else:
            from penx_app.scanners.tools import TOOLS_MENU
            with scanner_cancellation() as event:
                result = run_plan(plan, menu=TOOLS_MENU, cancel_event=event)
        result = replace(result, plan_summary=PlanSummary(
            plan.profile_id, plan.profile_version, plan.max_parallelism, plan.global_budget_seconds))
        if args.raw_artifacts:
            from penx_app.storage.raw_artifacts import retain_artifacts
            result = retain_artifacts(result, args.raw_artifacts)
        report = scan_report(plan, result, redact=args.redact)
        report['exit_code'] = policy_exit(result, report['findings'], args.fail_on,
                                         findings_truncated=report['findings_truncated'])
        report['policy'] = {'fail_on': args.fail_on}
        formats = ('json', 'sarif') if args.format == 'both' else (args.format,)
        for fmt in formats:
            payload = report if fmt == 'json' else sarif_from_report(report)
            path = publish_unique(args.output, 'penx_scan', '.' + fmt,
                                  json.dumps(payload, ensure_ascii=True, indent=2) + '\n')
            print('Report: ' + str(path))
        return report['exit_code']
    except (ValueError, KeyError) as exc:
        if dispatched:
            print('[!] Scan/report failed: ' + type(exc).__name__)
            return 1
        print('[!] Scan configuration: ' + str(exc))
        return 2
    except KeyboardInterrupt:
        print('[!] Scan interrupted; coverage is incomplete.')
        return 5
    except Exception as exc:
        print('[!] Scan/report failed: ' + type(exc).__name__)
        return 1
