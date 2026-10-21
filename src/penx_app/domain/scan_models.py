"""Scanner-domain contracts independent of CLI, storage and network libraries."""
from __future__ import annotations
from dataclasses import asdict, dataclass
from enum import Enum
import json
import math
from typing import TYPE_CHECKING

from penx_app.domain.scan_diagnostics import (
    MAX_EVENTS_PER_ADAPTER,
    PlanSummary,
    ScannerRunEvent,
)

if TYPE_CHECKING:
    from penx_app.domain.evidence import EvidenceRecord


@dataclass(frozen=True)
class ScanRequest:
    target: str
    scanner_ids: tuple[str, ...]
    passive_only: bool = False
    active_consent: bool = False


@dataclass(frozen=True)
class ScannerResult:
    scanner_id: str
    text: str
    status: str
    evidence: bool
    display_name: str = ''
    duration_seconds: float | None = None
    exit_code: int | None = None
    diagnostics: str = ''
    evidence_records: tuple['EvidenceRecord', ...] = ()
    run_events: tuple[ScannerRunEvent, ...] = ()

    def __post_init__(self):
        if self.status not in ('COMPLETE', 'PARTIAL', 'FAILED'):
            raise ValueError('Invalid scanner outcome status')
        if self.status == 'FAILED' and self.evidence:
            raise ValueError('Failed adapters cannot provide usable evidence')
        if self.duration_seconds is not None:
            if (not isinstance(self.duration_seconds, (int, float))
                    or isinstance(self.duration_seconds, bool)
                    or not math.isfinite(self.duration_seconds)
                    or self.duration_seconds < 0):
                raise ValueError('Invalid scanner execution duration')
        if self.exit_code is not None and type(self.exit_code) is not int:
            raise ValueError('Invalid scanner exit code')
        if not isinstance(self.diagnostics, str) or len(self.diagnostics) > 2000:
            raise ValueError('Invalid scanner diagnostic text')
        if not isinstance(self.evidence_records, tuple):
            raise ValueError('Invalid scanner evidence records')
        if not isinstance(self.run_events, tuple) \
                or len(self.run_events) > MAX_EVENTS_PER_ADAPTER:
            raise ValueError('Invalid scanner run events')
        if any(not isinstance(event, ScannerRunEvent)
               or event.scanner_id != self.scanner_id
               for event in self.run_events):
            raise ValueError('Run event does not match adapter')


@dataclass(frozen=True)
class ScanResult:
    results: tuple[ScannerResult, ...]
    plan_summary: PlanSummary | None = None

    @property
    def has_evidence(self) -> bool:
        return any(result.evidence for result in self.results)

    def metadata(self) -> str:
        """Persist source-matched bounded anchors without copying full raw outputs.

        Version 1 stays available for historical scans without provenance.
        Version 2 carries the same adapter outcomes plus source anchors.
        Version 3 (additive) adds bounded lifecycle events per adapter and a
        top-level plan summary; event-free results stay byte-identical v1/v2.
        """
        if len(self.results) > 100:
            raise ValueError('Too many scanner metadata records')
        rows = []
        version = 1
        for result in self.results:
            row = {'id': result.scanner_id, 'name': result.display_name,
                   'status': result.status, 'evidence': result.evidence}
            if result.evidence_records:
                if len(result.evidence_records) > 4:
                    raise ValueError('Too many evidence anchors for one adapter')
                if any(not record.matches(result) for record in result.evidence_records):
                    raise ValueError('Evidence anchor does not match adapter output')
                row['records'] = [asdict(record) for record in result.evidence_records]
                version = 2
            rows.append(row)
        if any(result.run_events for result in self.results) \
                or self.plan_summary is not None:
            version = 3
        if version == 3:
            for row, result in zip(rows, self.results):
                row['events'] = [event.to_dict()
                                 for event in result.run_events]
        payload = {'version': version, 'adapters': rows}
        if version == 3 and self.plan_summary is not None:
            payload['plan'] = asdict(self.plan_summary)
        encoded = json.dumps(payload, ensure_ascii=True)
        if len(encoded) > 100_000:
            raise ValueError('Scanner metadata exceeds its size limit')
        return encoded

    @classmethod
    def from_metadata(cls, text: str) -> ScanResult:
        if len(text) > 100_000:
            raise ValueError('Scanner metadata exceeds its size limit')
        value = json.loads(text)
        if not isinstance(value, dict) or type(value.get('version')) is not int \
                or value['version'] not in (1, 2, 3):
            raise ValueError('Unsupported scanner metadata version')
        version = value['version']
        rows = value.get('adapters')
        if not isinstance(rows, list) or len(rows) > 100:
            raise ValueError('Invalid scanner metadata')
        plan_summary: PlanSummary | None = None
        if version == 3:
            raw_plan = value.get('plan')
            if raw_plan is not None:
                if not isinstance(raw_plan, dict) or set(raw_plan) != {
                        'profile_id', 'profile_version',
                        'max_parallelism', 'global_budget_seconds'}:
                    raise ValueError('Invalid plan metadata')
                try:
                    plan_summary = PlanSummary(**raw_plan)
                except (TypeError, ValueError) as exc:
                    raise ValueError('Invalid plan metadata') from exc
        results = []
        for row in rows:
            if (not isinstance(row, dict) or not isinstance(row.get('id'), str)
                    or not isinstance(row.get('name'), str)
                    or not isinstance(row.get('status'), str)
                    or type(row.get('evidence')) is not bool):
                raise ValueError('Invalid scanner metadata record')
            # Historical anchors are stored claims. Without fresh source text
            # this parser does not independently reverify their raw offsets.
            evidence_records: tuple['EvidenceRecord', ...] = ()
            run_events: tuple[ScannerRunEvent, ...] = ()
            if version == 1:
                if 'records' in row or 'events' in row:
                    raise ValueError(
                        'Legacy metadata cannot contain anchors or run events')
            elif version == 2 and 'events' in row:
                raise ValueError('Metadata version 2 cannot contain run events')
            if version in (2, 3):
                from penx_app.domain.evidence import EvidenceRecord
                raw_records = row.get('records', [])
                if not isinstance(raw_records, list) or len(raw_records) > 4:
                    raise ValueError('Invalid evidence metadata records')
                collected = []
                expected_fields = {'scanner_id', 'kind', 'parser_version',
                                   'raw_start', 'raw_end', 'quote', 'host', 'port'}
                for raw_record in raw_records:
                    if not isinstance(raw_record, dict) or set(raw_record) != expected_fields:
                        raise ValueError('Unexpected evidence metadata fields')
                    try:
                        record = EvidenceRecord(**raw_record)
                    except (TypeError, ValueError) as exc:
                        raise ValueError('Invalid evidence metadata record') from exc
                    if (record.scanner_id != row['id'] or not row['evidence']
                            or row['status'] == 'FAILED'):
                        raise ValueError('Evidence metadata contradicts scanner outcome')
                    collected.append(record)
                evidence_records = tuple(collected)
            if version == 3:
                raw_events = row.get('events')
                if not isinstance(raw_events, list) \
                        or len(raw_events) > MAX_EVENTS_PER_ADAPTER:
                    raise ValueError('Invalid run event metadata')
                events = []
                for raw_event in raw_events:
                    try:
                        event = ScannerRunEvent.from_dict(raw_event)
                    except (TypeError, ValueError) as exc:
                        raise ValueError('Invalid run event metadata') from exc
                    if event.scanner_id != row['id']:
                        raise ValueError('Run event does not match adapter')
                    events.append(event)
                run_events = tuple(events)
            # Dataclass validates the allowed status/evidence combinations.
            results.append(ScannerResult(row['id'], '', row['status'],
                                         row['evidence'], row['name'],
                                         evidence_records=evidence_records,
                                         run_events=run_events))
        return cls(tuple(results), plan_summary=plan_summary)

    def evidence_records(self) -> tuple['EvidenceRecord', ...]:
        """In-memory provenance anchors attached at the adapter boundary."""
        return tuple(record for result in self.results
                     for record in result.evidence_records)

    def coverage(self) -> dict:
        completed = [(r.display_name or r.scanner_id).upper() for r in self.results if r.status == 'COMPLETE']
        failed = [(r.display_name or r.scanner_id).upper() for r in self.results if r.status != 'COMPLETE']
        return {'status': 'PARTIAL' if failed else ('COMPLETE' if completed else 'UNKNOWN'),
                'completed': completed, 'failed': failed,
                'note': ('Some selected scanners failed; absence of findings is inconclusive.'
                         if failed else 'Only selected scanners are covered; unselected scanners were not run.')}


class ReconText(str):
    """Legacy text boundary retaining trusted adapter results until persisted."""
    result: ScanResult

    def __new__(cls, value: str, result: ScanResult):
        instance = super().__new__(cls, value)
        instance.result = result
        return instance


class ScannerOutput(str):
    """String-compatible scanner output with trusted adapter outcome metadata.

    The formatting boundary serializes this metadata for stored reports.
    Existing string consumers and isolated tests remain compatible.
    """
    status: str
    evidence: bool
    scanner_id: str
    duration_seconds: float | None
    exit_code: int | None
    diagnostics: str
    evidence_records: tuple

    def __new__(cls, text: str, *, status: str = "COMPLETE",
                evidence: bool = True, scanner_id: str = '',
                duration_seconds: float | None = None,
                exit_code: int | None = None, diagnostics: str = '',
                evidence_records: tuple['EvidenceRecord', ...] = ()):
        if status not in {"COMPLETE", "PARTIAL", "FAILED"}:
            raise ValueError("Invalid scanner outcome status")
        if not isinstance(evidence_records, tuple):
            raise ValueError("Invalid scanner evidence records")
        # Do not turn None or arbitrary objects into seemingly valid
        # scanner text. Empty output cannot establish adapter evidence.
        if not isinstance(text, str):
            raise TypeError("Scanner output must be text")
        value = str.__new__(cls, text)
        value.status = status
        value.evidence = bool(evidence) and status != "FAILED" and bool(text.strip())
        value.scanner_id = scanner_id
        value.duration_seconds = duration_seconds
        value.exit_code = exit_code
        value.diagnostics = diagnostics
        value.evidence_records = evidence_records
        # The dataclass validates the carried metadata, not just the text.
        ScannerResult(scanner_id, str(value), status, value.evidence, '',
                      duration_seconds, exit_code, diagnostics,
                      evidence_records)
        return value


class ReconChoice(Enum):
    """Explicit tool-picker choice separate from scanner output."""
    PASSIVE_ONLY = "passive_only"

