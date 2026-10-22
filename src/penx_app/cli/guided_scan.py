"""Optional beginner wizard, delegating collection to the existing headless path."""
from __future__ import annotations

import argparse
import ipaddress
from collections.abc import Callable

from penx_app.application.preflight import build_preflight, format_report
from penx_app.application.scan_guidance import GOALS, RESULT_GUIDANCE, explain_profile, recommend_profile
from penx_app.application.scan_profiles import profile_to_plan
from penx_app.cli.cli_navigation import is_back, navigation_input
from penx_app.scanners.registry import CONSENT_KEYS
from penx_app.scanners.scanner_targets import normalize_host


def run_guided(*, target: str | None = None, output: str = './reports',
               ask: Callable[[str], str] = navigation_input,
               emit: Callable[[str], None] = print, execute=None) -> int:
    """Return without dispatch on back/EOF/declined consent or confirmation."""
    try:
        emit('Guided scan: choose scope, inspect the plan, then decide whether to start.')
        emit('Use only systems you own or have explicit permission to assess. Esc/back cancels.')
        raw_target = target if target is not None else ask('Single authorized hostname or IP: ')
        if is_back(raw_target) or not raw_target.strip():
            emit('Cancelled; no scanners started.')
            return 0
        if '/' in raw_target or '://' in raw_target:
            raise ValueError('Guided mode accepts one hostname or IP. Use advanced mode for URLs or subnets.')
        if ':' in raw_target:
            try:
                ipaddress.ip_address(raw_target.strip('[]'))
            except ValueError:
                raise ValueError('Use a hostname/IP without a port in guided mode.') from None
        host = normalize_host(raw_target)
        emit('Exact target for this run: ' + host)
        for key, (profile_id, explanation) in GOALS.items():
            emit(f'[{key}] {profile_id}: {explanation}')
        goal = ask('Goal [1: first inventory]: ').strip() or '1'
        if is_back(goal):
            emit('Cancelled; no scanners started.')
            return 0
        profile = recommend_profile(goal)
        emit(explain_profile(profile))
        consent_needed = bool(CONSENT_KEYS.intersection(profile.scanner_keys))
        answer = ask('Do you have permission to assess this exact target? [y/N]: ').strip().casefold()
        if answer not in ('y', 'yes'):
            emit('Cancelled; authorization was not confirmed.')
            return 0
        if consent_needed:
            answer = ask('Allow the additional active web checks described above? [y/N]: ').strip().casefold()
            if answer not in ('y', 'yes'):
                emit('Cancelled; active-check consent was not given.')
                return 0
        plan = profile_to_plan(profile, host, active_consent=consent_needed)
        preflight = build_preflight(plan)
        emit(format_report(preflight))
        emit('Reports will be written to: ' + output)
        emit('This collection runs without AI and creates no saved assessment session.')
        emit(RESULT_GUIDANCE)
        if not preflight.available:
            emit('Missing scanners reduce coverage. Install their prerequisites before relying on the result.')
            answer = ask('Continue with potentially incomplete coverage? [y/N]: ').strip().casefold()
            if answer not in ('y', 'yes'):
                emit('Cancelled; resolve missing prerequisites and preview again.')
                return 0
        answer = ask('Start this exact plan now? [y/N]: ').strip().casefold()
        if answer not in ('y', 'yes'):
            emit('Cancelled; no scanners started.')
            return 0
        if execute is None:
            from penx_app.application.headless_scan import main
            execute = main
        arguments = ['--target', host, '--authorized', '--profile', profile.id,
                     '--output', output, '--format', 'both']
        if consent_needed:
            arguments.append('--consent')
        code = execute(arguments)
        emit({0: 'Collection completed. Review the reports and evidence before drawing conclusions.',
              1: 'Collection or report writing failed; the result may be unavailable.',
              2: 'The plan or authorization was rejected; review the configuration.',
              3: 'The configured finding policy was exceeded; independently review applicability.',
              4: 'At least one scanner failed. The reports describe incomplete coverage.',
              5: 'Coverage is partial or the run was interrupted; absence of findings is inconclusive.'}.get(code, 'Review the collection outcome.'))
        return code
    except (EOFError, KeyboardInterrupt):
        emit('Cancelled or interrupted. Review any existing reports for partial coverage.')
        return 5
    except (ValueError, KeyError) as exc:
        emit('Guided scan: ' + str(exc))
        return 2


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog='penx guided', description=__doc__)
    parser.add_argument('--target')
    parser.add_argument('--output', default='./reports')
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    return run_guided(target=args.target, output=args.output)
