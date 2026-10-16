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
            note = f"[!] {name} was not started: scan cancelled by caller."
            emit(note)
            results[name] = ScannerOutput(
                note, status="PARTIAL", evidence=False,
                scanner_id=SCANNERS[key].id,
                diagnostics="Not started: caller cancelled scan sequence",
            )
            continue
        # Keep the menu function standalone (also used by isolated CLI tests).
        # Only trust previously collected HTTP/WhatWeb/Nmap evidence; no extra
        # probe is made solely to decide whether the target is resource-limited.
        overloaded = any(
            ("508 resource limit is reached" in str(output).casefold() or
             str(output).lstrip().startswith("HTTP 508 "))
            for label, output in results.items()
            if label.lower() in {"http headers", "web fingerprint", "nmap"}
        )
        if SCANNERS[key].resource_sensitive and overloaded:
            note = ("[!] Skipped active HTTP checks: previous selected probes observed "
                    "HTTP 508 Resource Limit Is Reached. Avoid additional load; "
                    "retry after the target recovers. No scan was run.")
            emit(f"\n[!] Skipping {name}: HTTP 508 resource limit already observed.")
            results[name] = ScannerOutput(
                note, status="PARTIAL", evidence=False,
                scanner_id=SCANNERS[key].id,
                diagnostics="Skipped after HTTP 508 from a previous selected scanner",
            )
            continue
        emit(f'\n[*] Running {name}...')
        started = time.monotonic()
        try:
            output = _call_adapter(runner, request.target, cancel_event)
            if not isinstance(output, ScannerOutput):
                failed = str(output).lstrip().startswith(('[!', '[EXIT CODE', '[ERROR]', 'Traceback '))
                output = ScannerOutput(str(output), status='FAILED' if failed else 'COMPLETE',
                                       evidence=bool(str(output).strip()) and not failed)
            results[name] = ScannerOutput(
                str(output), status=output.status, evidence=output.evidence,
                scanner_id=SCANNERS[key].id,
                duration_seconds=time.monotonic() - started,
                exit_code=output.exit_code, diagnostics=output.diagnostics,
            )
        except Exception as exc:
            # A broken optional adapter must not discard evidence from earlier
            # scanners or throw the user back to the main menu.
            detail = re.sub(r"[\x00-\x1f\x7f]+", " ", str(exc))[:220]
            message = f"[!] {name} failed ({type(exc).__name__}): {detail}"
            emit(message)
            results[name] = ScannerOutput(
                message, status="FAILED", evidence=False,
                scanner_id=SCANNERS[key].id,
                duration_seconds=time.monotonic() - started,
                diagnostics=detail,
            )
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
