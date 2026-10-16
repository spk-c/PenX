"""Read-only input contracts for evaluation and distillation exports.

SQL and connection lifetime stay in storage; text generation stays in
reporting. Use explicit vulnerability columns to tolerate legacy schema order.
"""
from __future__ import annotations
from contextlib import closing

from penx_app.storage.db import get_connection
from penx_app.storage.db_backend import (
    CORRECTION_COLUMNS, EVALUATION_COLUMNS, FIX_COLUMNS, VULNERABILITY_COLUMNS,
)
from penx_app.storage.session_repository import (
    CorrectionRecord, EvaluationRecord, Finding, FixRecord,
)


def load_evaluation_package(sl_no: int, *, connection_factory=None) -> dict:
    factory = connection_factory or get_connection
    with closing(factory()) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM history WHERE sl_no = %s", (sl_no,))
        history = cursor.fetchone()
        if history is None:
            return {"history": None, "summary": None, "vulns": [],
                    "fixes": [], "corrections": [], "evaluations": []}
        cursor.execute(
            "SELECT raw_scan, ai_analysis, risk_level, model_name "
            "FROM summary WHERE sl_no = %s", (sl_no,))
        summary = cursor.fetchone()
        if summary is None:
            return {"history": history, "summary": None, "vulns": [],
                    "fixes": [], "corrections": [], "evaluations": []}
        cursor.execute(f"SELECT {VULNERABILITY_COLUMNS} FROM vulnerabilities WHERE sl_no = %s", (sl_no,))
        vulns = tuple(Finding(*row) for row in cursor.fetchall())
        cursor.execute(f"SELECT {FIX_COLUMNS} FROM fixes WHERE sl_no = %s", (sl_no,))
        fixes = tuple(FixRecord(*row) for row in cursor.fetchall())
        cursor.execute(f"SELECT {CORRECTION_COLUMNS} FROM corrections WHERE sl_no = %s", (sl_no,))
        corrections = tuple(CorrectionRecord(*row) for row in cursor.fetchall())
        cursor.execute(f"SELECT {EVALUATION_COLUMNS} FROM evaluations WHERE sl_no = %s", (sl_no,))
        evaluations = tuple(EvaluationRecord(*row) for row in cursor.fetchall())
        return dict(history=history, summary=summary, vulns=vulns, fixes=fixes,
                    corrections=corrections, evaluations=evaluations)


def load_distillation_package(*, connection_factory=None) -> dict:
    factory = connection_factory or get_connection
    with closing(factory()) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT c.status, c.reason, v.vuln_name, v.severity, h.target, c.corrected_at
            FROM corrections c
            JOIN vulnerabilities v ON c.vuln_id = v.id
            JOIN history h ON c.sl_no = h.sl_no
            ORDER BY c.corrected_at DESC
        """)
        corrections = cursor.fetchall()
        cursor.execute("SELECT id, rule_text, source, created_at FROM learned_rules ORDER BY id")
        rules = cursor.fetchall()
        return {"corrections": corrections, "rules": rules}
