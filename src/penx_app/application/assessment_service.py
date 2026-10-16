"""Assessment lifecycle independent of terminal, database and model implementations."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Callable
from penx_app.domain.scan_models import ReconText


@dataclass(frozen=True)
class AssessmentPorts:
    create_session: Callable
    analyse: Callable
    save: Callable
    discard: Callable
    preserve_assessment: Callable
    export: Callable
    notify: Callable = lambda event, value: None


@dataclass(frozen=True)
class AssessmentOutcome:
    session_id: int | None
    completed: bool
    stage: str
    assessment: dict = field(default_factory=dict)
    counts: dict = field(default_factory=dict)
    reports: dict = field(default_factory=dict)
    error: BaseException | None = None


def run_assessment(target: str, raw_scan: str, coverage: dict, *,
                   passive_only: bool, model_name: str,
                   ports: AssessmentPorts) -> AssessmentOutcome:
    """Commit once, preserve failed results, and export only after commit.

    Selection, consent and collection precede this use case. No input or print
    calls are needed; callers receive a stage-specific result on every exit.
    """
    try:
        session_id = ports.create_session(target, status='pending')
        if type(session_id) is not int or session_id < 1:
            raise ValueError('Storage did not return a positive session ID')
    except (Exception, KeyboardInterrupt) as exc:
        ports.notify('reservation_failed', exc)
        return AssessmentOutcome(None, False, 'reserve', error=exc)
    ports.notify('reserved', session_id)

    def discard_pending() -> None:
        try:
            ports.discard(session_id, raw_scan)
        except (Exception, KeyboardInterrupt) as cleanup_error:
            # The original analysis/save failure stays authoritative. A failed
            # best-effort cleanup is surfaced independently for recovery.
            ports.notify('cleanup_failed', cleanup_error)

    try:
        result = (ports.analyse(target, raw_scan, passive_only=True) if passive_only
                  else ports.analyse(target, raw_scan))
    except (Exception, KeyboardInterrupt) as exc:
        ports.notify('analysis_failed', exc)
        discard_pending()
        return AssessmentOutcome(session_id, False, 'analysis', error=exc)

    ports.notify('saving', session_id)
    try:
        result['raw_scan'] = str(raw_scan)
        # Never accept a model-supplied status record; only the adapter boundary
        # can produce metadata. Legacy callers explicitly have no metadata.
        result['scan_metadata'] = raw_scan.result.metadata() if isinstance(raw_scan, ReconText) else ''
        result['full_response'] = str(result.get('full_response') or '') + (
            '\n\n[SCAN COVERAGE]\n' + coverage['status'] + '\n' + coverage['note']
            + '\nFailed: ' + ', '.join(coverage['failed']))
        counts = ports.save(session_id, result, model_name=model_name)
    except (Exception, KeyboardInterrupt) as exc:
        ports.notify('save_failed', exc)
        try:
            ports.preserve_assessment(session_id, result)
        except Exception as backup_exc:
            ports.notify('backup_failed', backup_exc)
        discard_pending()
        return AssessmentOutcome(session_id, False, 'save', error=exc)

    ports.notify('saved', (session_id, counts, result))
    try:
        reports = ports.export(session_id)
    except Exception as exc:
        ports.notify('export_failed', exc)
        return AssessmentOutcome(session_id, True, 'export', result, counts, error=exc)
    ports.notify('exported', reports)
    return AssessmentOutcome(session_id, True, 'complete', result, counts, reports)
