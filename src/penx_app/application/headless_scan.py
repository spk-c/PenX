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
from penx_app.domain.scan_models import ScanResult, ScannerResult
from penx_app.file_output import publish_unique
from penx_app.reporting.machine_reports import _mask, sarif_from_report
from penx_app.scanners.scanner_targets import normalize_host

SEVERITIES = {'info': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
_TEMPLATE = re.compile(r'^TEMPLATE ([^|]{1,180}) \| (info|low|medium|high|critical) \| (.{1,500}) \| (.{1,1000})$')


def scan_report(plan, result: ScanResult, *, redact: bool = False) -> dict:
    """Report adapter observations; only Nuclei template matches have severity.

    Raw banners, errors and inventory are never interpreted as vulnerabilities.
    A template match still requires independent human applicability review.
    """
    findings: list[dict] = []
    for adapter in result.results:
        if adapter.scanner_id != 'nuclei' or not adapter.evidence or adapter.status == 'FAILED':
            continue
        for line in adapter.text[:1_048_576].splitlines():
            match = _TEMPLATE.fullmatch(line)
            if not match:
                continue
            template, severity, name, location = (part.strip() for part in match.groups())
            fingerprint = finding_fingerprint(template, location, 'nuclei', target=plan.target)
            findings.append({
                'id': len(findings) + 1, 'rule': 'PENX-NUCLEI-' + template,
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
            })
            if len(findings) >= 1000:
                break
    return {
        'schema': 'penx-scan-v1', 'session': None,
        'target': _mask(plan.target, plan.target, redact),
        'scan_date': datetime.now(timezone.utc).isoformat(),
        'profile': asdict(result.plan_summary) if result.plan_summary else None,
        'coverage': result.coverage(),
        'adapters': [{'id': row.scanner_id, 'status': row.status, 'evidence': row.evidence,
                      'diagnostics': _mask(row.diagnostics, plan.target, redact),
                      'raw_artifact': asdict(row.raw_artifact) if row.raw_artifact else None}
                     for row in result.results],
        'findings': findings, 'php2shell': None,
        'limitations': [
            'Headless collection runs without AI and creates no saved assessment session.',
            'Only explicit Nuclei template matches are severity-rated; other adapters supply coverage only.',
            'No matches does not establish absence of vulnerabilities.',
            'Hashes attest integrity against trusted references, not exploitability.',
        ],
    }


def policy_exit(result: ScanResult, findings: list[dict], threshold: str | None) -> int:
    """Error > incomplete coverage > finding policy > successful collection."""
    if any(row.status == 'FAILED' for row in result.results):
        return 4
    if not result.results or any(row.status != 'COMPLETE' for row in result.results):
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
    parser.add_argument('--authorized', action='store_true', help='Confirm authorization for this exact target')
    parser.add_argument('--consent', action='store_true', help='Authorize consent-gated active web checks')
    parser.add_argument('--output', default='./reports')
    parser.add_argument('--format', choices=('json', 'sarif', 'both'), default='json')
    parser.add_argument('--redact', action='store_true')
    parser.add_argument('--fail-on', choices=tuple(SEVERITIES))
    parser.add_argument('--max-parallelism', type=int, default=1)
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
        plan = _build_plan(target, profile=args.profile, scanners=args.scanners, consent=args.consent)
        plan = replace(plan, max_parallelism=args.max_parallelism,
                       global_budget_seconds=args.budget,
                       dispatch_interval_seconds=args.dispatch_interval)
        from penx_app.domain.scan_plan import assert_valid_plan
        assert_valid_plan(plan)
        if args.dry_run:
            preflight = build_preflight(plan)
            print(format_report(preflight))
            return 0 if preflight.available else 4
        if not args.authorized:
            raise ValueError('Pass --authorized only for targets you own or have explicit permission to assess.')
        if plan.passive_only and (args.budget is not None or args.max_parallelism != 1
                                  or args.dispatch_interval is not None):
            raise ValueError('Passive providers do not support planner budgets, parallelism or dispatch intervals.')
        dispatched = True
        if plan.passive_only:
            # Passive providers have no typed completion/cancellation contract.
            # Preserve that uncertainty; never promote text to COMPLETE.
            from penx_app.scanners.passive_recon import passive_recon
            text = passive_recon(plan.target, include_paid=False)
            result = ScanResult((ScannerResult('passive_recon', text, 'PARTIAL', False,
                                               'Passive recon', diagnostics='Provider coverage is not independently verified'),))
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
        report['exit_code'] = policy_exit(result, report['findings'], args.fail_on)
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
