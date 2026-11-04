"""One explicit read contract for stored sessions, shared by all consumers."""
from __future__ import annotations
from contextlib import closing, contextmanager
from dataclasses import dataclass
import sqlite3
from typing import NamedTuple
from penx_app.domain.scan_models import ScanResult
from penx_app.storage.db_backend import SQLiteConnection
from penx_app.storage.db_backend import (
    CORRECTION_COLUMNS, EVALUATION_COLUMNS, EXPLOIT_COLUMNS, FIX_COLUMNS,
    SUMMARY_COLUMNS, VULNERABILITY_COLUMNS,
)


class History(NamedTuple):
    session_id: int
    target: str
    scan_date: str
    status: str


@dataclass(frozen=True)
class HistoryPage:
    """One bounded keyset page, not a full history/materialized snapshot."""
    entries: tuple[History, ...]
    next_before_id: int | None


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


@contextmanager
def _consistent_sqlite_read(connection):
    """Read all session tables from one SQLite snapshot.

    Python sqlite3 legacy transaction mode only starts an implicit transaction
    for writes, so consecutive SELECT queries otherwise see different commits.
    Explicit BEGIN pins the read view once the first SELECT runs. Roll back
    our read-only transaction even if deserialization or a SELECT fails.
    Other database backends retain their existing transaction semantics.
    """
    sqlite = isinstance(connection, (SQLiteConnection, sqlite3.Connection))
    if sqlite:
        connection.execute("BEGIN")
    try:
        yield
    finally:
        if sqlite:
            connection.rollback()


class SessionRepository:
    def __init__(self, connection_factory):
        self.connection_factory = connection_factory

    def snapshot(self, session_id: int) -> SessionSnapshot:
        with closing(self.connection_factory()) as connection:
            with _consistent_sqlite_read(connection):
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

    def history_page(
        self, *, limit: int = 50, before_id: int | None = None,
        status: str = "active", target: str | None = None,
        from_date: str | None = None, until_date: str | None = None,
    ) -> HistoryPage:
        """Bounded, deterministic history paging without fetching scan contents.

        Keyset paging is stable under inserts: newer session IDs never
        displace older pages. This is not a consistent snapshot across calls.
        """
        from datetime import date, timedelta

        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("History page limit must be between 1 and 100")
        if before_id is not None and (
                type(before_id) is not int or before_id <= 0):
            raise ValueError("Invalid history cursor")
        if status not in {"active", "pending"}:
            raise ValueError("Invalid history status")
        if target is not None and (
                not isinstance(target, str) or not target
                or len(target) > 1024
                or any(ord(ch) < 32 for ch in target)):
            raise ValueError("Invalid exact target filter")
        for candidate in (from_date, until_date):
            if candidate is not None:
                if not isinstance(candidate, str) or len(candidate) != 10:
                    raise ValueError("Invalid ISO date filter")
                try:
                    parsed = date.fromisoformat(candidate)
                except ValueError as exc:
                    raise ValueError("Invalid ISO date filter") from exc
                if parsed.isoformat() != candidate:
                    raise ValueError("Invalid ISO date filter")
        if from_date and until_date and from_date > until_date:
            raise ValueError("Date range is reversed")
        predicates = ["status = %s"]
        params: list[object] = [status]
        if before_id is not None:
            predicates.append("sl_no < %s")
            params.append(before_id)
        if target is not None:
            predicates.append("target = %s")
            params.append(target)
        if from_date is not None:
            predicates.append("scan_date >= %s")
            params.append(from_date)
        if until_date is not None:
            # ISO scan_date values may contain local time, so inclusive
            # calendar end uses a next-day strict upper bound.
            day = date.fromisoformat(until_date)
            if day == date.max:
                raise ValueError("History end date is not representable")
            predicates.append("scan_date < %s")
            params.append((day + timedelta(days=1)).isoformat())
        sql = ("SELECT sl_no, target, scan_date, status FROM history WHERE "
               + " AND ".join(predicates)
               + " ORDER BY sl_no DESC LIMIT %s")
        params.append(limit + 1)
        with closing(self.connection_factory()) as connection:
            cursor = connection.cursor()
            try:
                cursor.execute(sql, tuple(params))
                rows = cursor.fetchmany(limit + 1)
            finally:
                cursor.close()
        if not isinstance(rows, (list, tuple)) or len(rows) > limit + 1:
            raise ValueError("Invalid bounded history page")
        entries = tuple(History(*row) for row in rows[:limit])
        return HistoryPage(
            entries=entries,
            next_before_id=entries[-1].session_id if len(rows) > limit else None,
        )

    def history(self) -> list[History]:
        with closing(self.connection_factory()) as connection:
            cursor = connection.cursor()
            cursor.execute('SELECT sl_no, target, scan_date, status FROM history '
                           'WHERE status = %s ORDER BY sl_no DESC', ('active',))
            return [History(*row) for row in cursor.fetchall()]


def table_row_counts(connection) -> dict[str, int]:
    """Read-only per-table row counts; works on any legacy or current schema."""
    tables = [
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' "
            "AND name NOT LIKE 'sqlite_%' ORDER BY name"
        )
    ]
    return {
        table: connection.execute(
            f'SELECT COUNT(*) FROM "{table}"'
        ).fetchone()[0]
        for table in tables
    }
