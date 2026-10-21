"""Sequential scanner execution; consent is enforced before the first adapter."""
import inspect
import re
import threading
import time
from dataclasses import replace
from penx_app.domain.evidence import capture_evidence
from penx_app.domain.scan_models import ScanRequest, ScannerOutput, ScannerResult, ScanResult
from penx_app.scanners.registry import SCANNERS, CONSENT_KEYS


def _call_adapter(runner, target: str, cancel_event: threading.Event | None):
    """Propagate only to adapters explicitly declaring a cancellation port.

    Never retry a call with different arguments after TypeError: it might
    hide an adapter crash and accidentally dispatch the same scan twice.
    """
    if cancel_event is not None:
        try:
            accepts_cancel = "cancel_event" in inspect.signature(runner).parameters
        except (TypeError, ValueError):
            accepts_cancel = False
        if accepts_cancel:
            return runner(target, cancel_event=cancel_event)
    return runner(target)


def _overload_observed(rows: dict) -> bool:
    """True when a completed selected probe already reported HTTP 508."""
    return any(
        ("508 resource limit is reached" in str(output).casefold() or
         re.search(r"(?im)^HTTP\s+508(?:\s|$)", str(output)))
        for label, output in rows.items()
        if label.lower() in {"http headers", "web fingerprint", "nmap"}
    )


def _cancelled_row(name: str, scanner_id: str) -> tuple[str, ScannerOutput]:
    note = f"[!] {name} was not started: scan cancelled by caller."
    return note, ScannerOutput(
        note, status="PARTIAL", evidence=False,
        scanner_id=scanner_id,
        diagnostics="Not started: caller cancelled scan sequence",
    )


def _overload_skip_row(name: str, scanner_id: str) -> tuple[str, ScannerOutput]:
    note = ("[!] Skipped active HTTP checks: previous selected probes observed "
            "HTTP 508 Resource Limit Is Reached. Avoid additional load; "
            "retry after the target recovers. No scan was run.")
    return note, ScannerOutput(
        note, status="PARTIAL", evidence=False,
        scanner_id=scanner_id,
        diagnostics="Skipped after HTTP 508 from a previous selected scanner",
    )


def _run_adapter(name: str, runner, target: str, emit,
                 cancel_event: threading.Event | None,
                 scanner_id: str) -> ScannerOutput:
    """Run one adapter with the established normalization and isolation."""
    emit(f'\n[*] Running {name}...')
    started = time.monotonic()
    try:
        output = _call_adapter(runner, target, cancel_event)
        if not isinstance(output, ScannerOutput):
            # Legacy adapters may return plain text, but None, false,
            # empty containers and arbitrary object reprs are never
            # trustworthy completed scanner evidence.
            if not isinstance(output, str):
                output = ScannerOutput(
                    f"[!] Unsupported scanner result type: {type(output).__name__}",
                    status="FAILED", evidence=False,
                    diagnostics="Adapter did not return ScannerOutput or text",
                )
            else:
                failed = (not output.strip() or
                          output.lstrip().startswith(('[!', '[EXIT CODE', '[ERROR]', 'Traceback ')))
                output = ScannerOutput(
                    output, status='FAILED' if failed else 'COMPLETE',
                    evidence=not failed,
                )
        return ScannerOutput(
            str(output), status=output.status, evidence=output.evidence,
            scanner_id=scanner_id,
            duration_seconds=time.monotonic() - started,
            exit_code=output.exit_code, diagnostics=output.diagnostics,
        )
    except Exception as exc:
        # A broken optional adapter must not discard evidence from earlier
        # scanners or throw the user back to the main menu.
        detail = re.sub(r"[\x00-\x1f\x7f]+", " ", str(exc))[:220]
        message = f"[!] {name} failed ({type(exc).__name__}): {detail}"
        emit(message)
        return ScannerOutput(
            message, status="FAILED", evidence=False,
            scanner_id=scanner_id,
            duration_seconds=time.monotonic() - started,
            diagnostics=detail,
        )


def run_selected(request: ScanRequest, *, menu: dict, emit=lambda *_: None,
                 cancel_event: threading.Event | None = None) -> dict:
    if request.passive_only:
        raise ValueError('Passive collection cannot dispatch active scanner adapters.')
    if not request.scanner_ids or any(key not in menu or key not in SCANNERS for key in request.scanner_ids):
        raise ValueError('Invalid scanner selection. No scanners started.')
    if CONSENT_KEYS.intersection(request.scanner_ids) and not request.active_consent:
        raise ValueError('Active checks require explicit consent before any scanner starts.')
    results: dict[str, ScannerOutput] = {}
    for key in dict.fromkeys(request.scanner_ids):
        name, runner = menu[key]
        if cancel_event is not None and cancel_event.is_set():
            # Preserve selected-scanner coverage without executing the next
            # adapter after a caller cancelled the running scan sequence.
            note, row = _cancelled_row(name, SCANNERS[key].id)
            emit(note)
            results[name] = row
            continue
        # Keep the menu function standalone (also used by isolated CLI tests).
        # Only trust previously collected HTTP/WhatWeb/Nmap evidence; no extra
        # probe is made solely to decide whether the target is resource-limited.
        if SCANNERS[key].resource_sensitive and _overload_observed(results):
            note, row = _overload_skip_row(name, SCANNERS[key].id)
            emit(f"\n[!] Skipping {name}: HTTP 508 resource limit already observed.")
            results[name] = row
            continue
        results[name] = _run_adapter(name, runner, request.target, emit,
                                     cancel_event, SCANNERS[key].id)
    return results


def run_selected_structured(request: ScanRequest, *, menu: dict,
                            emit=lambda *_: None,
                            cancel_event: threading.Event | None = None) -> ScanResult:
    """Run validated selected adapters and retain authoritative statuses.

    The previous dict/string menu contract delegates here. Untrusted scanner
    output text is never parsed to recover structured trusted status.
    """
    rendered = run_selected(request, menu=menu, emit=emit,
                            cancel_event=cancel_event)
    rows = []
    for name, output in rendered.items():
        row = ScannerResult(
            scanner_id=output.scanner_id,
            text=str(output),
            status=output.status,
            evidence=output.evidence,
            display_name=name,
            duration_seconds=output.duration_seconds,
            exit_code=output.exit_code,
            diagnostics=output.diagnostics,
        )
        # Attach a bounded provenance anchor for every adapter that produced
        # usable evidence; failed or empty adapters carry no records.
        if row.evidence and row.text.strip():
            record = capture_evidence(
                row, 0, min(2000, len(row.text)),
                kind="adapter_output", parser_version=1,
            )
            row = replace(row, evidence_records=(record,))
        rows.append(row)
    return ScanResult(tuple(rows))
