"""One explicit read contract for stored sessions, shared by all consumers."""
from __future__ import annotations
from contextlib import closing
from dataclasses import dataclass
from typing import NamedTuple
from penx_app.domain.scan_models import ScanResult
from penx_app.storage.db_backend import (
    CORRECTION_COLUMNS, EVALUATION_COLUMNS, EXPLOIT_COLUMNS, FIX_COLUMNS,
    SUMMARY_COLUMNS, VULNERABILITY_COLUMNS,
)


class History(NamedTuple):
    session_id: int
    target: str
    scan_date: str
    status: str


class Finding(NamedTuple):
    id: int
    session_id: int
    name: str
    severity: str
    confidence: str
    port: str
    service: str
    description: str


class FixRecord(NamedTuple):
    id: int
    session_id: int
    vuln_id: int
    fix_text: str
    source: str


class ExploitRecord(NamedTuple):
    id: int
    session_id: int
    exploit_name: str
    tool_used: str
    payload: str
    result: str
    notes: str


class CorrectionRecord(NamedTuple):
    id: int
    session_id: int
    vuln_id: int
    status: str
    original_text: str
    corrected_text: str
    reason: str
    corrected_at: str


class EvaluationRecord(NamedTuple):
    id: int
    session_id: int
    vuln_id: int
    evaluator: str
    evidence_cited: str
    verdict: str
    confidence: str
    severity_correct: str
    cve_correct: str
    software_correct: str
    fix_correct: str
    notes: str
    evaluated_at: str


class Summary(NamedTuple):
    id: int
    session_id: int
    raw_scan: str
    analysis: str
    risk_level: str
    model_name: str
    generated_at: str


@dataclass(frozen=True)
class SessionSnapshot:
    history: History | None
    findings: tuple[Finding, ...]
    fixes: tuple[FixRecord, ...]
    exploits: tuple[ExploitRecord, ...]
    summary: Summary | None
    corrections: tuple[CorrectionRecord, ...]
    evaluations: tuple[EvaluationRecord, ...]
    scan_result: ScanResult | None = None

    def as_legacy(self) -> dict:
        """One conversion point for existing tuple/dictionary clients."""
        return dict(history=self.history, vulns=list(self.findings),
                    fixes=list(self.fixes), exploits=list(self.exploits),
                    summary=self.summary, corrections=list(self.corrections),
                    evaluations=list(self.evaluations), scan_result=self.scan_result)


class SessionRepository:
    def __init__(self, connection_factory):
        self.connection_factory = connection_factory

    def snapshot(self, session_id: int) -> SessionSnapshot:
        with closing(self.connection_factory()) as connection:
            cursor = connection.cursor()
            # Explicit column lists keep legacy and freshly created schemas equal.
            cursor.execute('SELECT sl_no, target, scan_date, status FROM history WHERE sl_no = %s', (session_id,))
            row = cursor.fetchone()
            history = History(*row) if row else None
            cursor.execute(f'SELECT {VULNERABILITY_COLUMNS} FROM vulnerabilities WHERE sl_no = %s',
                           (session_id,))
            findings = tuple(Finding(*row) for row in cursor.fetchall())
            cursor.execute(f'SELECT {FIX_COLUMNS} FROM fixes WHERE sl_no = %s', (session_id,))
            fixes = tuple(FixRecord(*row) for row in cursor.fetchall())
            cursor.execute(f'SELECT {EXPLOIT_COLUMNS} FROM exploits_attempted WHERE sl_no = %s',
                           (session_id,))
            exploits = tuple(ExploitRecord(*row) for row in cursor.fetchall())
            cursor.execute(f'SELECT {SUMMARY_COLUMNS} FROM summary WHERE sl_no = %s ORDER BY id DESC',
                           (session_id,))
            row = cursor.fetchone()
            summary = Summary(*row) if row else None
            cursor.execute(f'SELECT {CORRECTION_COLUMNS} FROM corrections WHERE sl_no = %s '
                           'ORDER BY corrected_at', (session_id,))
            corrections = tuple(CorrectionRecord(*row) for row in cursor.fetchall())
            cursor.execute(f'SELECT {EVALUATION_COLUMNS} FROM evaluations WHERE sl_no = %s '
                           'ORDER BY evaluated_at', (session_id,))
            evaluations = tuple(EvaluationRecord(*row) for row in cursor.fetchall())
            cursor.execute('SELECT scan_metadata FROM summary WHERE sl_no = %s', (session_id,))
            metadata = cursor.fetchone()
            scan_result = ScanResult.from_metadata(metadata[0]) if metadata and metadata[0] else None
            return SessionSnapshot(history, findings, fixes, exploits, summary, corrections, evaluations, scan_result)

    def history(self) -> list[History]:
        with closing(self.connection_factory()) as connection:
            cursor = connection.cursor()
            cursor.execute('SELECT sl_no, target, scan_date, status FROM history '
                           'WHERE status = %s ORDER BY sl_no DESC', ('active',))
            return [History(*row) for row in cursor.fetchall()]
