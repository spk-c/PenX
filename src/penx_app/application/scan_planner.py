"""Plan-based scan scheduling and bounded parallel execution.

`run_plan` executes a validated `ScanPlan`. With `max_parallelism == 1` and
no budget/dispatch-interval fields it delegates to the existing sequential
executor (`run_selected_structured`) so behavior is unchanged. Any plan that
uses a budget or a dispatch interval, or parallelism > 1, goes through the
bounded scheduler in this module.
"""
import concurrent.futures
import os
import re
import threading
import time
from dataclasses import dataclass, replace

from penx_app.application.scanner_execution import (
    _call_adapter,
    _cancelled_row,
    _overload_observed,
    _overload_skip_row,
    _run_adapter,
    run_selected_structured,
)
from penx_app.domain.evidence import capture_evidence
from penx_app.domain.scan_diagnostics import (
    MAX_EVENTS_PER_ADAPTER,
    PlanSummary,
    ScannerRunEvent,
)
from penx_app.domain.scan_models import ScannerOutput, ScannerResult, ScanResult
from penx_app.domain.scan_plan import (
    TIMEOUT_MAX_SECONDS,
    TIMEOUT_MIN_SECONDS,
    PlanValidationError,
    ScanPlan,
    validate_plan,
)
from penx_app.scanners.registry import SCANNERS
from penx_app.domain.scanner_configuration import ScannerConfiguration
from penx_app.scanners.configuration_runtime import configured_adapter

# Built-in per-node defaults mirroring the adapter-level deadlines already
# applied by the adapters in scanners/tools.py (sequential mode).
_BUILTIN_TIMEOUTS = {
    'nmap': 180, 'whois': 120, 'whatweb': 60, 'http_headers': 120,
    'dns': 60, 'nikto': 300, 'nuclei': 240, 'httpx': 45, 'ffuf': 70,
    'endpoint_mapping': 180, 'subfinder': 135, 'katana': 90, 'tls': 60,
}
_DEFAULT_TIMEOUT = 300


@dataclass(frozen=True)
class PlannedNode:
    key: str
    position: int          # index in build_schedule output
    timeout_seconds: int   # resolved per R7/env/default


def build_schedule(plan: ScanPlan) -> tuple[str, ...]:
    """Stable topological order; dependencies never add scanners to scope."""
    errors = validate_plan(plan)
    if errors:
        raise PlanValidationError('; '.join(errors))
    schedule: list[str] = []
    pending = [key for key in SCANNERS if key in plan.scanner_keys]
    while pending:
        ready = next(key for key in pending if not any(
            child == key and parent in pending for child, parent in plan.dependencies))
        schedule.append(ready)
        pending.remove(ready)
    return tuple(schedule)


def plan_nodes(plan: ScanPlan) -> tuple[PlannedNode, ...]:
    """Scheduled nodes in plan order with resolved per-node timeouts."""
    schedule = build_schedule(plan)
    return tuple(
        PlannedNode(key=key, position=position,
                    timeout_seconds=resolve_node_timeout(plan, key))
        for position, key in enumerate(schedule)
    )


def resolve_node_timeout(plan: ScanPlan, key: str) -> int:
    """Effective per-node timeout: plan override > env > built-in default.

    The env layer mirrors scanners/tools.py: PENX_<ID_UPPER>_TIMEOUT,
    clamped to 30..900 seconds.
    """
    override = plan.per_scanner_timeouts.get(key)
    if override is not None:
        return override
    spec = SCANNERS[key]
    raw = os.environ.get(f'PENX_{spec.id.upper()}_TIMEOUT', '').strip()
    if raw:
        try:
            value = int(raw)
        except ValueError:
            value = None
        if value is not None:
            return max(TIMEOUT_MIN_SECONDS, min(value, TIMEOUT_MAX_SECONDS))
    return _BUILTIN_TIMEOUTS.get(spec.id, _DEFAULT_TIMEOUT)


def run_plan(plan: ScanPlan, *, menu: dict, emit=lambda *_: None,
             cancel_event: threading.Event | None = None) -> ScanResult:
    """Execute a validated plan; rows always come back in plan order."""
    errors = validate_plan(plan)
    if errors:
        raise PlanValidationError('; '.join(errors))
    if plan.passive_only:
        raise ValueError(
            'Passive collection cannot dispatch active scanner adapters.')
    if any(key not in menu for key in plan.scanner_keys):
        raise ValueError('Invalid scanner selection. No scanners started.')
    configurations = {item.scanner_key: item for item in plan.scanner_configuration}
    for key, timeout in plan.per_scanner_timeouts.items():
        configurations[key] = replace(configurations.get(key, ScannerConfiguration(key)),
                                      timeout_seconds=timeout)
    if configurations:
        configured_menu = dict(menu)
        for key, options in configurations.items():
            if key not in menu:
                raise ValueError('Configured scanner missing from adapter menu')
            def bind(runner, config):
                def run(target, *, cancel_event=None):
                    with configured_adapter(config):
                        return _call_adapter(runner, target, cancel_event)
                return run
            configured_menu[key] = (menu[key][0], bind(menu[key][1], options))
        menu = configured_menu
        timeouts = dict(plan.per_scanner_timeouts)
        timeouts.update({key: options.timeout_seconds for key, options in configurations.items()
                         if options.timeout_seconds is not None})
        plan = replace(plan, per_scanner_timeouts=timeouts)
    if (plan.max_parallelism == 1
            and plan.global_budget_seconds is None
            and plan.dispatch_interval_seconds is None and not plan.dependencies):
        if configurations:
            result = _run_plan_scheduled(plan, menu=menu, emit=emit, cancel_event=cancel_event)
            return replace(result, scanner_configuration=tuple(configurations[key] for key in sorted(configurations)))
        # Zero-behavior-change path: the existing sequential executor.
        return run_selected_structured(plan.to_request(), menu=menu,
                                       emit=emit, cancel_event=cancel_event)
    result = _run_plan_scheduled(plan, menu=menu, emit=emit, cancel_event=cancel_event)
    return replace(result, scanner_configuration=tuple(configurations[key] for key in sorted(configurations)))


def _terminal_event(output: ScannerOutput) -> str:
    """Map a finalized adapter row to its bounded run-event name."""
    if output.status == 'FAILED':
        return 'failed'
    diagnostics = output.diagnostics
    if 'cancel' in diagnostics.lower():
        return 'cancelled'
    if 'Timed out' in diagnostics:
        return 'failed'
    if diagnostics.startswith('Not started:') or '508' in diagnostics:
        return 'skipped'
    return 'completed'


def _run_plan_scheduled(plan: ScanPlan, *, menu: dict, emit,
                        cancel_event: threading.Event | None) -> ScanResult:
    schedule = build_schedule(plan)
    names = {key: menu[key][0] for key in schedule}
    ids = {key: SCANNERS[key].id for key in schedule}
    node_timeout = {key: resolve_node_timeout(plan, key) for key in schedule}
    started = time.monotonic()
    deadline = None
    if plan.global_budget_seconds is not None:
        deadline = started + plan.global_budget_seconds

    # One cooperative stop path for adapters: the caller's event when
    # provided, otherwise an internal one. The budget deadline also trips it
    # (cooperative stop, no hard kill).
    effective_cancel = (cancel_event if cancel_event is not None
                        else threading.Event())

    emit_lock = threading.Lock()

    def safe_emit(*args) -> None:
        with emit_lock:
            emit(*args)

    rows: dict[str, ScannerOutput] = {}
    completed: dict[str, ScannerOutput] = {}
    events: dict[str, list[ScannerRunEvent]] = {}

    def record(key: str, output: ScannerOutput) -> None:
        rows[key] = output
        completed[names[key]] = output
        duration = (time.monotonic() - started_at[key]
                   if key in started_at else None)
        events.setdefault(key, []).append(ScannerRunEvent(
            ids[key], _terminal_event(output), duration,
            output.exit_code, output.diagnostics[:200]))
        # Bounded per adapter (metadata v3 cap), newest events kept.
        del events[key][MAX_EVENTS_PER_ADAPTER:]

    pending = list(schedule)
    in_flight: dict[str, concurrent.futures.Future] = {}
    started_at: dict[str, float] = {}
    last_start: float | None = None
    workers = max(1, plan.max_parallelism)

    class NodeCancellation(threading.Event):
        def is_set(self):
            return super().is_set() or effective_cancel.is_set()

        def wait(self, timeout=None):
            until = time.monotonic() + timeout if timeout is not None else None
            while not self.is_set():
                remaining = until - time.monotonic() if until is not None else 0.05
                if remaining <= 0:
                    break
                super().wait(min(0.05, remaining))
            return self.is_set()

    node_events: dict[str, NodeCancellation] = {}

    with concurrent.futures.ThreadPoolExecutor(
            max_workers=workers) as pool:
        while pending or in_flight:
            if deadline is not None and time.monotonic() >= deadline:
                effective_cancel.set()
            # Reap finished or timed-out nodes first so fresh 508 evidence is
            # visible before the next dispatch decision.
            for key, future in list(in_flight.items()):
                if future.done():
                    in_flight.pop(key)
                    if key in rows:
                        continue
                    try:
                        record(key, future.result())
                    except Exception as exc:
                        detail = re.sub(r'[\x00-\x1f\x7f]+', ' ',
                                        str(exc))[:220]
                        record(key, ScannerOutput(
                            f"[!] {names[key]} failed "
                            f"({type(exc).__name__}): {detail}",
                            status="FAILED", evidence=False,
                            scanner_id=ids[key],
                            diagnostics=detail))
                elif key not in rows and (time.monotonic() - started_at[key]
                      >= node_timeout[key]):
                    # Retain the occupied worker until it actually exits;
                    # otherwise timed-out work could exceed parallelism.
                    node_events[key].set()
                    timeout = node_timeout[key]
                    note = (f"[!] {names[key]} timed out after "
                            f"{timeout} seconds.")
                    safe_emit(note)
                    record(key, ScannerOutput(
                        note, status="PARTIAL", evidence=False,
                        scanner_id=ids[key],
                        diagnostics=(
                            f"Timed out after {timeout} seconds "
                            "(cooperative stop requested)")))
            if in_flight:
                done, _ = concurrent.futures.wait(
                    list(in_flight.values()),
                    timeout=0.05,
                    return_when=concurrent.futures.FIRST_COMPLETED)
                for key, future in list(in_flight.items()):
                    if future in done:
                        in_flight.pop(key)
                        if key in rows:
                            continue
                        try:
                            record(key, future.result())
                        except Exception as exc:
                            detail = re.sub(r'[\x00-\x1f\x7f]+', ' ',
                                            str(exc))[:220]
                            record(key, ScannerOutput(
                                f"[!] {names[key]} failed "
                                f"({type(exc).__name__}): {detail}",
                                status="FAILED", evidence=False,
                                scanner_id=ids[key],
                                diagnostics=detail))
            if not pending and not in_flight:
                break
            while pending and len(in_flight) < workers:
                ready = [key for key in pending if not any(
                    child == key and (parent not in rows or parent in in_flight)
                    for child, parent in plan.dependencies)]
                if not ready:
                    break
                key = ready[0]
                name = names[key]
                spec = SCANNERS[key]
                now = time.monotonic()
                if effective_cancel.is_set() and (deadline is None or now < deadline):
                    note, output_row = _cancelled_row(name, ids[key])
                    safe_emit(note)
                    record(key, output_row)
                    pending.remove(key)
                    continue
                if deadline is not None and now >= deadline:
                    note = (f"[!] {name} was not started: global budget "
                            "exhausted.")
                    safe_emit(note)
                    effective_cancel.set()
                    record(key, ScannerOutput(
                        note, status="PARTIAL", evidence=False,
                        scanner_id=ids[key],
                        diagnostics="Not started: global budget exhausted"))
                    pending.remove(key)
                    continue
                failed_dependencies = [parent for child, parent in plan.dependencies
                                       if child == key and rows[parent].status != 'COMPLETE']
                if failed_dependencies:
                    record(key, ScannerOutput('Not started: prerequisite did not complete',
                           status='PARTIAL', evidence=False, scanner_id=ids[key],
                           diagnostics='Not started: failed prerequisite ' + ','.join(failed_dependencies)))
                    pending.remove(key)
                    continue
                if spec.resource_sensitive and _overload_observed(completed):
                    _, output_row = _overload_skip_row(name, ids[key])
                    safe_emit(f"\n[!] Skipping {name}: HTTP 508 resource "
                              "limit already observed.")
                    record(key, output_row)
                    pending.remove(key)
                    continue
                if (plan.dispatch_interval_seconds is not None
                        and last_start is not None):
                    wait = (last_start + plan.dispatch_interval_seconds
                            - time.monotonic())
                    if wait > 0:
                        if deadline is not None:
                            wait = min(wait, max(0, deadline - time.monotonic()))
                        effective_cancel.wait(wait)
                        continue  # Recheck cancellation and budget before dispatch.
                last_start = time.monotonic()
                started_at[key] = last_start
                events.setdefault(key, []).append(ScannerRunEvent(
                    ids[key], 'started', None, None,
                    f"dispatched as node {schedule.index(key) + 1}/"
                    f"{len(schedule)}"[:200]))
                node_events[key] = NodeCancellation()
                in_flight[key] = pool.submit(
                    _run_adapter, name, menu[key][1], plan.target,
                    safe_emit, node_events[key], ids[key])
                pending.remove(key)

    ordered = []
    for key in schedule:
        output = rows[key]
        row = ScannerResult(
            scanner_id=output.scanner_id,
            text=str(output),
            status=output.status,
            evidence=output.evidence,
            display_name=names[key],
            duration_seconds=output.duration_seconds,
            exit_code=output.exit_code,
            diagnostics=output.diagnostics,
            run_events=tuple(events.get(key, ())),
        )
        if row.evidence and row.text.strip():
            anchored = capture_evidence(
                row, 0, min(2000, len(row.text)),
                kind="adapter_output", parser_version=1,
            )
            row = replace(row, evidence_records=(anchored,))
        ordered.append(row)
    plan_summary = PlanSummary(
        plan.profile_id, plan.profile_version, plan.max_parallelism,
        plan.global_budget_seconds)
    return ScanResult(tuple(ordered), plan_summary=plan_summary, dependencies=plan.dependencies)
