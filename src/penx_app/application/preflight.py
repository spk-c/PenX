"""Offline preflight / dry-run availability reporting for validated plans.

`build_preflight` never dispatches a scanner adapter and never opens a network
connection. It reuses the existing local resolvers (binary lookup, interpreter
detection, library import checks) plus best-effort bounded version probes, so a
caller can see exactly which scheduled scanners can run before any scan
starts. Runtime *banner* versions stay in intelligence/finding_trace.py
(post-scan); preflight reports *binary* versions.
"""
from __future__ import annotations

import argparse
import importlib.util
import os
import sys
from dataclasses import dataclass
from pathlib import Path

from penx_app.application.scan_planner import build_schedule
from penx_app.application.scan_profiles import (
    build_custom_plan,
    get_profile,
    profile_to_plan,
)
from penx_app.domain.scan_plan import PlanValidationError, ScanPlan
from penx_app.scanners import tools as _tools
from penx_app.scanners.process_runner import run_tool
from penx_app.scanners.registry import CONSENT_KEYS, SCANNERS
from penx_app.scanners.scanner_runtime import (
    NIKTO_SCRIPT,
    WHATWEB_SCRIPT,
    find_nmap,
    find_runtime,
    npcap_present,
)


@dataclass(frozen=True)
class ScannerAvailability:
    key: str
    scanner_id: str
    display_name: str
    available: bool
    version: str | None          # best effort, local binary version
    missing: tuple[str, ...]     # e.g. ('nmap',) or ('ruby', 'vendor/whatweb/whatweb')
    note: str                    # <= 200 chars


@dataclass(frozen=True)
class PreflightReport:
    plan: ScanPlan
    schedule: tuple[str, ...]
    availability: tuple[ScannerAvailability, ...]   # one per scheduled key, plan order
    available: bool              # True iff all scheduled scanners are available


_DISPLAY = {
    '1': 'Nmap', '2': 'WHOIS', '3': 'WhatWeb', '4': 'HTTP headers',
    '5': 'DNS', '6': 'Nikto', '7': 'Nuclei', '8': 'HTTPx',
    '9': 'FFuf', 'e': 'Endpoint mapping', 's': 'Subfinder',
    'c': 'Katana', 'd': 'TLS check',
}

_BUILTIN_NOTE = 'available (Python stdlib, no external binary)'


def _builtin_version() -> str:
    return f'python-{sys.version_info.major}.{sys.version_info.minor} (builtin)'


def _probe_version(binary: str, flag: str) -> str | None:
    """Bounded local version probe; failure never changes availability."""
    try:
        result = run_tool([binary, flag], timeout=10)
    except Exception:
        return None
    status = getattr(result, 'status', None)
    if status is not None and status != 'COMPLETE':
        return None
    for line in str(result).splitlines():
        line = line.strip()
        if line:
            return line[:200]
    return None


def _nmap() -> ScannerAvailability:
    path = find_nmap()
    if not path:
        return ScannerAvailability(
            '1', 'nmap', _DISPLAY['1'], False, None, ('nmap',),
            'nmap binary not found. Install Nmap or set PENX_NMAP_PATH.'[:200])
    note = 'Nmap available'
    if os.name == 'nt' and not npcap_present():
        note += ' (Npcap not detected; some scan types may fail)'
    return ScannerAvailability('1', 'nmap', _DISPLAY['1'], True,
                               _probe_version(path, '--version'), (), note[:200])


def _library(key: str, module: str, missing_label: str) -> ScannerAvailability:
    name = _DISPLAY[key]
    if importlib.util.find_spec(module) is not None:
        return ScannerAvailability(key, SCANNERS[key].id, name, True, None, (),
                                   f'{name} library available'[:200])
    return ScannerAvailability(key, SCANNERS[key].id, name, False, None,
                               (missing_label,),
                               f'{missing_label} package not installed'[:200])


def _builtin(key: str) -> ScannerAvailability:
    return ScannerAvailability(key, SCANNERS[key].id, _DISPLAY[key], True,
                               _builtin_version(), (), _BUILTIN_NOTE[:200])


def _script_scanner(key: str, interpreter: str, script: 'Path',
                    script_label: str) -> ScannerAvailability:
    name = _DISPLAY[key]
    missing: list[str] = []
    runtime = find_runtime(interpreter)
    script_ok = script.is_file()
    if not runtime:
        missing.append(interpreter)
    if not script_ok:
        missing.append(script_label)
    available = bool(runtime) and script_ok
    version = _probe_version(runtime, '--version') if runtime else None
    if available:
        note = f'{name} available ({interpreter} + bundled script)'
    elif len(missing) == 2:
        note = f'{name} missing: {interpreter} and {script_label}'
    else:
        note = f'{name} missing: {missing[0]}'
    return ScannerAvailability(key, SCANNERS[key].id, name, available, version,
                               tuple(missing), note[:200])


def _go_tool(key: str) -> ScannerAvailability:
    spec = SCANNERS[key]
    name = _DISPLAY[key]
    path = _tools.tool_path(spec.id)
    if not path:
        return ScannerAvailability(
            key, spec.id, name, False, None, (spec.id,),
            f'{name} binary not found. Install it or set '
            f'PENX_{spec.id.upper()}_PATH.'[:200])
    return ScannerAvailability(key, spec.id, name, True,
                               _probe_version(path, '-version'), (),
                               f'{name} available'[:200])


def scanner_availability(key: str) -> ScannerAvailability:
    """Availability of one registry key, in plan-independent terms."""
    if key not in SCANNERS:
        raise KeyError(f'Unknown scanner key: {key!r}')
    if key == '1':
        return _nmap()
    if key == '2':
        return _library('2', 'whois', 'python-whois')
    if key == '3':
        return _script_scanner('3', 'ruby', WHATWEB_SCRIPT,
                               'vendor/whatweb/whatweb')
    if key == '4':
        return _builtin('4')
    if key == '5':
        return _library('5', 'dns', 'dnspython')
    if key == '6':
        return _script_scanner('6', 'perl', NIKTO_SCRIPT,
                               'vendor/nikto/program/nikto.pl')
    if key == 'e':
        # Python-only path (crawler binaries are their own registry keys).
        return _library('e', 'requests', 'requests')
    if key == 'd':
        return _builtin('d')
    return _go_tool(key)


def build_preflight(plan: ScanPlan) -> PreflightReport:
    """Dry-run availability for a validated plan. No adapters, no network."""
    schedule = build_schedule(plan)
    availability = tuple(scanner_availability(key) for key in schedule)
    return PreflightReport(plan=plan, schedule=schedule,
                           availability=availability,
                           available=all(item.available for item in availability))


def format_report(report: PreflightReport) -> str:
    plan = report.plan
    lines = [
        'PenX preflight (dry run): no scanner started, no network used.',
        f'Target: {plan.target} (host as given; no normalization applied)',
        f'Profile: {plan.profile_id} v{plan.profile_version}',
        'Plan: ' + ', '.join((
            f'consent={"yes" if plan.active_consent else "no"}',
            f'passive={"yes" if plan.passive_only else "no"}',
            f'max_parallelism={plan.max_parallelism}',
            'global_budget=' + ('off' if plan.global_budget_seconds is None
                                else f'{plan.global_budget_seconds}s'),
            'dispatch_interval=' + ('off' if plan.dispatch_interval_seconds is None
                                    else f'{plan.dispatch_interval_seconds}s'),
        )),
        'Schedule order: ' + (', '.join(report.schedule) or '(none - passive)'),
    ]
    for item in report.availability:
        mark = 'ok' if item.available else 'MISSING'
        parts = [f'[{mark}] {item.display_name} ({item.scanner_id})']
        if item.version:
            parts.append('version=' + item.version)
        if not item.available and item.missing:
            parts.append('missing: ' + ', '.join(item.missing))
        if item.note:
            parts.append(item.note)
        lines.append('  ' + ' | '.join(parts))
    for options in plan.scanner_configuration:
        lines.append('  Scanner configuration: ' + str(options.to_dict()))
    for child, parent in plan.dependencies:
        lines.append(f'  Dependency: {child} requires completed {parent}')
    consent_keys = [key for key in report.schedule if key in CONSENT_KEYS]
    if consent_keys:
        lines.append('Consent reminder: consent-gated active scanners selected: '
                     + ', '.join(_DISPLAY[key] for key in consent_keys) + '.')
    lines.append('Result: ' + ('ALL SCHEDULED SCANNERS AVAILABLE'
                               if report.available
                               else 'ONE OR MORE SCHEDULED SCANNERS MISSING'))
    return '\n'.join(lines)


def _build_plan(target: str, *, profile: str | None, scanners: str | None,
                consent: bool) -> ScanPlan:
    if scanners is not None:
        keys = tuple(dict.fromkeys(part.strip()
                                   for part in scanners.split(',')
                                   if part.strip()))
        if not keys:
            raise ValueError('No scanner keys supplied.')
        unknown = [key for key in keys if key not in SCANNERS]
        if unknown:
            raise ValueError('Unknown scanner key(s): ' + ', '.join(unknown))
        return build_custom_plan(target, keys, active_consent=consent)
    profile_id = profile if profile is not None else 'standard'
    profile_spec = get_profile(profile_id)
    return profile_to_plan(profile_spec, target, active_consent=consent)


def main(argv: list[str]) -> int:
    """Headless entry point for `penx preflight ...`.

    Exit codes: 0 = plan valid and all scheduled scanners available (or a
    passive plan); 1 = plan/config error or a scheduled scanner missing;
    2 = usage error.
    """
    parser = argparse.ArgumentParser(
        prog='penx preflight',
        description='Offline preflight: validate a scan plan and report '
                    'scanner availability without starting any scanner.')
    parser.add_argument('--target', required=True,
                        help='Target host or domain as given')
    parser.add_argument('--profile', default=None,
                        help='Built-in profile id (default: standard)')
    parser.add_argument('--scanners', default=None,
                        help='Comma-separated scanner keys, e.g. 1,3,d')
    parser.add_argument('--consent', action='store_true',
                        help='Authorize consent-gated active scanners')
    try:
        args = parser.parse_args(argv)
    except SystemExit:
        return 2
    target = args.target.strip()
    if not target:
        print('[!] Preflight usage: --target must not be empty.')
        return 2
    try:
        plan = _build_plan(target, profile=args.profile, scanners=args.scanners,
                           consent=args.consent)
    except PlanValidationError as exc:
        print('[!] Plan error: ' + str(exc))
        return 1
    except KeyError as exc:
        print('[!] ' + str(exc))
        return 1
    except ValueError as exc:
        print('[!] ' + str(exc))
        return 1
    report = build_preflight(plan)
    print(format_report(report))
    return 0 if report.available else 1
