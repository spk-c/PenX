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
    """Dispatch order for a validated plan.

    Phase 1 keeps registry order filtered by the plan keys, deduplicated and
    stable. Dependency-aware ordering is a later phase; the signature stays
    stable.
    """
    errors = validate_plan(plan)
    if errors:
        raise PlanValidationError('; '.join(errors))
    seen: set[str] = set()
    schedule: list[str] = []
    for key in SCANNERS:
        if key in plan.scanner_keys and key not in seen:
            schedule.append(key)
            seen.add(key)
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
    if (plan.max_parallelism == 1
            and plan.global_budget_seconds is None
            and plan.dispatch_interval_seconds is None):
        # Zero-behavior-change path: the existing sequential executor.
        return run_selected_structured(plan.to_request(), menu=menu,
                                       emit=emit, cancel_event=cancel_event)
    missing = [key for key in plan.scanner_keys if key not in menu]
    if missing:
        raise ValueError('Invalid scanner selection. No scanners started.')
    return _run_plan_scheduled(plan, menu=menu, emit=emit,
                               cancel_event=cancel_event)


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

    with concurrent.futures.ThreadPoolExecutor(
            max_workers=workers) as pool:
        while pending or in_flight:
            # Reap finished or timed-out nodes first so fresh 508 evidence is
            # visible before the next dispatch decision.
            for key, future in list(in_flight.items()):
                if future.done():
                    in_flight.pop(key)
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
                elif (time.monotonic() - started_at[key]
                      >= node_timeout[key]):
                    in_flight.pop(key)
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
                key = pending[0]
                name = names[key]
                spec = SCANNERS[key]
                if effective_cancel.is_set():
                    note, output_row = _cancelled_row(name, ids[key])
                    safe_emit(note)
                    record(key, output_row)
                    pending.pop(0)
                    continue
                now = time.monotonic()
                if deadline is not None and now >= deadline:
                    note = (f"[!] {name} was not started: global budget "
                            "exhausted.")
                    safe_emit(note)
                    effective_cancel.set()
                    record(key, ScannerOutput(
                        note, status="PARTIAL", evidence=False,
                        scanner_id=ids[key],
                        diagnostics="Not started: global budget exhausted"))
                    pending.pop(0)
                    continue
                if spec.resource_sensitive and _overload_observed(completed):
                    _, output_row = _overload_skip_row(name, ids[key])
                    safe_emit(f"\n[!] Skipping {name}: HTTP 508 resource "
                              "limit already observed.")
                    record(key, output_row)
                    pending.pop(0)
                    continue
                if (plan.dispatch_interval_seconds is not None
                        and last_start is not None):
                    wait = (last_start + plan.dispatch_interval_seconds
                            - time.monotonic())
                    if wait > 0:
                        time.sleep(wait)
                last_start = time.monotonic()
                started_at[key] = last_start
                events.setdefault(key, []).append(ScannerRunEvent(
                    ids[key], 'started', None, None,
                    f"dispatched as node {schedule.index(key) + 1}/"
                    f"{len(schedule)}"[:200]))
                in_flight[key] = pool.submit(
                    _run_adapter, name, menu[key][1], plan.target,
                    safe_emit, effective_cancel, ids[key])
                pending.pop(0)

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
    return ScanResult(tuple(ordered), plan_summary=plan_summary)
