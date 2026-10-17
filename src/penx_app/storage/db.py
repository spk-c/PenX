#!/usr/bin/env python3
"""
PenX - db.py
MariaDB / SQLite connection + all read/write/edit/delete operations
Database: penx
"""

from contextlib import closing
from datetime import datetime
import sqlite3
import time
from penx_app.storage.db_backend import (
    CORRECTION_COLUMNS, EXPLOIT_COLUMNS, FIX_COLUMNS,
    get_connection, VULNERABILITY_COLUMNS,
)


# ─────────────────────────────────────────────
# CONNECTION
# ─────────────────────────────────────────────

# ─────────────────────────────────────────────
# WRITE FUNCTIONS
# ─────────────────────────────────────────────

def create_session(target: str, *, status: str = "active") -> int:
    """Insert a history row; pending assessments are hidden until committed."""
    if status not in ("active", "pending"):
        raise ValueError("Invalid session status.")
    with closing(get_connection()) as conn:
        c = conn.cursor()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c.execute(
            "INSERT INTO history (target, scan_date, status) VALUES (%s, %s, %s)",
            (target, now, status)
        )
        conn.commit()
        sl_no = c.lastrowid
        return sl_no


def save_vulnerability(sl_no: int, vuln_name: str, severity: str,
                       port: str, service: str, description: str,
                       confidence: str = "possible") -> int:
    """Insert a vulnerability. Returns its id."""
    _validated("severity", severity)
    _validated("confidence", confidence)
    with closing(get_connection()) as conn:
        c = conn.cursor()
        c.execute("""
            INSERT INTO vulnerabilities (sl_no, vuln_name, severity, confidence, port, service, description)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (sl_no, vuln_name, severity, confidence, port, service, description))
        conn.commit()
        vuln_id = c.lastrowid
        return vuln_id


_SESSION_LOCK_RETRY_WINDOW_SECONDS = 0.5
_SESSION_LOCK_RETRY_INITIAL_SECONDS = 0.025


def _lock_session_writer(cursor, sl_no: int) -> None:
    """Acquire a session writer lock with short, bounded SQLite BUSY retries.

    Do not replay INSERT/UPDATE operations after their execution or commit:
    only this harmless lock-acquisition UPDATE may be repeated. In regular
    SQLite mode the driver already waits up to its configured busy_timeout;
    the extra retry budget only helps short busy_timeout connections.
    """
    deadline = time.monotonic() + _SESSION_LOCK_RETRY_WINDOW_SECONDS
    pause = _SESSION_LOCK_RETRY_INITIAL_SECONDS
    while True:
        try:
            cursor.execute("UPDATE history SET status = status WHERE sl_no = %s", (sl_no,))
            return
        except sqlite3.OperationalError as exc:
            # SQLITE_BUSY_SNAPSHOT and other extended errors cannot be
            # resolved by repeating the statement in the same transaction.
            if (getattr(exc, "sqlite_errorcode", None) != getattr(sqlite3, "SQLITE_BUSY", 5)
                    or time.monotonic() + pause >= deadline):
                raise
            time.sleep(pause)
            pause = min(2 * pause, 0.1)


def _assert_vulnerability_owner(cursor, sl_no: int, vuln_id: int) -> None:
    """Pin the session writer before checking a finding's ownership.

    In SQLite's legacy mode a SELECT does not begin a write transaction. If
    a second connection deletes the finding between this check and an INSERT,
    the caller can fail with a foreign-key error. Locking the owning history
    row serializes this check with finding deletion and evaluator imports,
    and is portable to MariaDB without SELECT FOR UPDATE.
    """
    _lock_session_writer(cursor, sl_no)
    cursor.execute("SELECT id FROM vulnerabilities WHERE id = %s AND sl_no = %s",
                   (vuln_id, sl_no))
    if cursor.fetchone() is None:
        raise ValueError("Finding does not belong to selected session.")


def save_fix(sl_no: int, vuln_id: int, fix_text: str, source: str = "ai"):
    """Insert a fix linked to a vulnerability."""
    with closing(get_connection()) as conn:
        c = conn.cursor()
        _assert_vulnerability_owner(c, sl_no, vuln_id)
        c.execute("""
            INSERT INTO fixes (sl_no, vuln_id, fix_text, source)
            VALUES (%s, %s, %s, %s)
        """, (sl_no, vuln_id, fix_text, source))
        conn.commit()


def save_exploit(sl_no, exploit_name, tool_used, payload, result, notes):
    with closing(get_connection()) as conn:
        c = conn.cursor()
        c.execute("""
            INSERT INTO exploits_attempted 
            (sl_no, exploit_name, tool_used, payload, result, notes)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (
            sl_no,
            str(exploit_name or "")[:1000],
            str(tool_used  or "")[:500],
            str(payload    or "")[:10000],
            str(result     or "")[:2000],
            str(notes      or "")
        ))
        conn.commit()


def _guard_create_once(cursor, sl_no: int) -> None:
    """Lock the owning history row before checking the create-once summary.

    Using an UPDATE instead of SELECT FOR UPDATE works with SQLite and
    MariaDB and serializes concurrent writers for the same session. The
    no-op UPDATE need not report any rows changed on MariaDB.
    """
    _lock_session_writer(cursor, sl_no)
    cursor.execute("SELECT sl_no FROM history WHERE sl_no = %s", (sl_no,))
    if cursor.fetchone() is None:
        raise ValueError("Assessment session does not exist.")
    cursor.execute("SELECT id FROM summary WHERE sl_no = %s", (sl_no,))
    if cursor.fetchone() is not None:
        raise ValueError("Assessment summary already exists for this session.")


def save_summary(sl_no: int, raw_scan: str, ai_analysis: str, risk_level: str,
                  model_name: str = ""):
    """Insert the full session summary."""
    _validated("risk_level", risk_level)
    with closing(get_connection()) as conn:
        c = conn.cursor()
        _guard_create_once(c, sl_no)
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c.execute("""
            INSERT INTO summary (sl_no, raw_scan, ai_analysis, risk_level, model_name, generated_at)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (sl_no, raw_scan, ai_analysis, risk_level, model_name, now))
        conn.commit()


def save_correction(sl_no: int, vuln_id: int, status: str,
                    original_text: str, corrected_text: str, reason: str) -> int:
    """
    Save a correction/hallucination record for a vulnerability.
    status: 'hallucination', 'corrected', 'verified', 'downgraded', 'reclassified'
    """
    _validated("status", status)
    with closing(get_connection()) as conn:
        c = conn.cursor()
        _assert_vulnerability_owner(c, sl_no, vuln_id)
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c.execute("""
            INSERT INTO corrections
            (sl_no, vuln_id, status, original_text, corrected_text, reason, corrected_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (sl_no, vuln_id, status, original_text, corrected_text, reason, now))
        conn.commit()
        cid = c.lastrowid
        print(f"[+] Correction id={cid} saved for vuln id={vuln_id} [{status}]")
        return cid



def save_assessment(sl_no: int, result: dict, *, model_name: str = "") -> dict:
    """Persist an AI assessment in ONE transaction, or roll back every write.

    A history row is reserved by the caller before analysis so failed raw
    scans can be archived with a session identifier. The caller removes the
    history row when this transaction fails; nothing is left half-written.
    """
    if not isinstance(result, dict):
        raise ValueError("Assessment response must be an object.")
    # An absent model risk is inconclusive; never invent a clean/low verdict.
    risk = str(result.get("risk_level") or "UNKNOWN").strip().upper()
    _validated("risk_level", risk)
    for key in ("vulnerabilities", "recommendations", "rejected_findings", "exploits"):
        if not isinstance(result.get(key, []), list):
            raise ValueError(f"Assessment {key} must be a list.")
    # Preserve the normalized outcome for callers that display the saved value.
    result["risk_level"] = risk
    raw_scan = str(result.get("raw_scan") or "")
    full_response = str(result.get("full_response") or "")
    conn = get_connection()
    counts = {"vulnerabilities": 0, "recommendations": 0,
              "rejected": 0, "corrections": 0, "exploits": 0}
    try:
        c = conn.cursor()
        # Check before inserting any vulnerability, fix or summary rows.
        _guard_create_once(c, sl_no)

        def finding(item: dict, *, recommendation: bool = False) -> int:
            if not isinstance(item, dict):
                raise ValueError("Finding must be an object.")
            severity = "info" if recommendation else str(item.get("severity") or "unknown").lower()
            confidence = "recommendation" if recommendation else str(item.get("confidence") or "possible").lower()
            if not str(item.get("vuln_name") or "").strip():
                raise ValueError("Finding missing its name.")
            _validated("severity", severity)
            _validated("confidence", confidence)
            c.execute(
                "INSERT INTO vulnerabilities "
                "(sl_no, vuln_name, severity, confidence, port, service, description) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s)",
                (sl_no, item["vuln_name"], severity, confidence,
                 str(item.get("port") or ""), str(item.get("service") or ""),
                 str(item.get("description") or ""))
            )
            vid = c.lastrowid
            if not recommendation and item.get("fix"):
                c.execute(
                    "INSERT INTO fixes (sl_no, vuln_id, fix_text, source) "
                    "VALUES (%s, %s, %s, %s)",
                    (sl_no, vid, item["fix"], "ai")
                )
            flag = str(item.get("_review_flag") or "").lower()
            if flag and flag != "valid":
                # Unknown model verdicts must not become silently trusted labels.
                _validated("status", flag)
                reason_parts = ["Auto-flagged by self-review"]
                if item.get("_review_issue"):
                    reason_parts.append("Issue: " + str(item["_review_issue"]))
                if item.get("_review_evidence"):
                    reason_parts.append("Evidence: " + str(item["_review_evidence"]))
                now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                c.execute(
                    "INSERT INTO corrections "
                    "(sl_no, vuln_id, status, original_text, corrected_text, reason, corrected_at) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s)",
                    (sl_no, vid, flag,
                     f"[{item.get('_review_original_severity') or severity}] {item.get('_review_original_name') or item['vuln_name']}: {item.get('_review_original_description', item.get('description', ''))}",
                     item.get("_review_corrected", ""),
                     " | ".join(reason_parts), now)
                )
                counts["corrections"] += 1
            return vid

        for item in result.get("vulnerabilities") or []:
            finding(item)
            counts["vulnerabilities"] += 1
        for item in result.get("recommendations") or []:
            finding(item, recommendation=True)
            counts["recommendations"] += 1
        for discarded in result.get("rejected_findings") or []:
            if not isinstance(discarded, dict):
                raise ValueError("Rejected finding must be an object.")
            if discarded.get("_review_flag") != "hallucination":
                continue
            archived = dict(discarded)
            archived["fix"] = ""
            finding(archived)
            counts["rejected"] += 1
        for exp in result.get("exploits") or []:
            if not isinstance(exp, dict):
                raise ValueError("Exploit record must be an object.")
            c.execute(
                "INSERT INTO exploits_attempted "
                "(sl_no, exploit_name, tool_used, payload, result, notes) "
                "VALUES (%s, %s, %s, %s, %s, %s)",
                (sl_no, str(exp.get("exploit_name") or "")[:1000],
                 str(exp.get("tool_used") or "")[:500], str(exp.get("payload") or ""),
                 str(exp.get("result") or "")[:2000], str(exp.get("notes") or ""))
            )
            counts["exploits"] += 1
        c.execute(
            "INSERT INTO summary "
            "(sl_no, raw_scan, ai_analysis, risk_level, model_name, generated_at) "
            "VALUES (%s, %s, %s, %s, %s, %s)",
            (sl_no, raw_scan, full_response,
             risk, model_name, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        )
        c.execute("UPDATE history SET status = %s WHERE sl_no = %s", ("active", sl_no))
        if c.rowcount != 1:
            raise ValueError("Reserved assessment session no longer exists.")
        metadata = result.get('scan_metadata') or ''
        if metadata:
            from penx_app.domain.scan_models import ScanResult
            ScanResult.from_metadata(metadata)  # Validate before committing any records.
            c.execute('UPDATE summary SET scan_metadata = %s WHERE sl_no = %s', (metadata, sl_no))
        conn.commit()
        return counts
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()


from penx_app.domain.finding_policy import active_vulnerabilities as active_vulnerabilities


# ─────────────────────────────────────────────
# READ FUNCTIONS
# ─────────────────────────────────────────────

def get_all_history():
    from penx_app.storage.session_repository import SessionRepository
    return SessionRepository(get_connection).history()


def get_session(sl_no: int) -> dict:
    from penx_app.storage.session_repository import SessionRepository
    return SessionRepository(get_connection).snapshot(sl_no).as_legacy()


def get_vulnerabilities(sl_no: int):
    with closing(get_connection()) as conn:
        c = conn.cursor()
        c.execute(f"SELECT {VULNERABILITY_COLUMNS} FROM vulnerabilities WHERE sl_no = %s", (sl_no,))
        rows = c.fetchall()
        return rows


def get_fixes(sl_no: int):
    from penx_app.storage.session_repository import FixRecord
    with closing(get_connection()) as conn:
        c = conn.cursor()
        c.execute(f"SELECT {FIX_COLUMNS} FROM fixes WHERE sl_no = %s", (sl_no,))
        return [FixRecord(*row) for row in c.fetchall()]


def get_exploits(sl_no: int):
    from penx_app.storage.session_repository import ExploitRecord
    with closing(get_connection()) as conn:
        c = conn.cursor()
        c.execute(f"SELECT {EXPLOIT_COLUMNS} FROM exploits_attempted WHERE sl_no = %s", (sl_no,))
        return [ExploitRecord(*row) for row in c.fetchall()]


def get_corrections(sl_no: int):
    from penx_app.storage.session_repository import CorrectionRecord
    with closing(get_connection()) as conn:
        c = conn.cursor()
        c.execute(f"SELECT {CORRECTION_COLUMNS} FROM corrections WHERE sl_no = %s "
                  "ORDER BY corrected_at", (sl_no,))
        return [CorrectionRecord(*row) for row in c.fetchall()]


# ─────────────────────────────────────────────
# EDIT FUNCTIONS
# ─────────────────────────────────────────────

# Validate enum values before they reach the database (also on direct API calls).
SEVERITIES = {"critical", "high", "medium", "low", "info", "unknown"}
CONFIDENCES = {"confirmed", "likely", "possible", "recommendation"}
CORRECTION_STATUSES = {"hallucination", "corrected", "verified", "downgraded", "reclassified"}
RISK_LEVELS = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}


def _validated(field: str, value: str) -> str:
    enum = {"severity": SEVERITIES, "confidence": CONFIDENCES,
            "status": CORRECTION_STATUSES, "risk_level": RISK_LEVELS}.get(field)
    if enum is not None and value not in enum:
        raise ValueError(f"Invalid {field}: {value!r}; expected one of {sorted(enum)}")
    return value


def _scoped_write(table: str, row_id: int, sl_no: int, changes: dict) -> bool:
    """Update a whitelisted table row owned by the current session."""
    allowed_tables = {"vulnerabilities", "fixes", "exploits_attempted", "corrections"}
    if table not in allowed_tables:
        raise ValueError("Invalid table")
    fields = ', '.join(f'{field} = %s' for field in changes)
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(f"UPDATE {table} SET {fields} WHERE id = %s AND sl_no = %s",
                       (*changes.values(), row_id, sl_no))
        updated = cursor.rowcount > 0
        if not updated:
            # MariaDB defaults to changed rows rather than FOUND_ROWS. An
            # unchanged value is still a successful edit of an existing row.
            cursor.execute(f"SELECT id FROM {table} WHERE id = %s AND sl_no = %s",
                           (row_id, sl_no))
            updated = cursor.fetchone() is not None
        conn.commit()
        return updated
    finally:
        conn.close()


def edit_vulnerability(vuln_id: int, field: str, value: str, *, sl_no: int):
    allowed = {"vuln_name", "severity", "confidence", "port", "service", "description"}
    if field not in allowed:
        raise ValueError(f"Invalid vulnerability field: {field}")
    return _scoped_write("vulnerabilities", vuln_id, sl_no, {field: _validated(field, value)})


def edit_fix(fix_id: int, fix_text: str, *, sl_no: int):
    return _scoped_write("fixes", fix_id, sl_no, {"fix_text": fix_text})


def edit_exploit(exploit_id: int, field: str, value: str, *, sl_no: int):
    allowed = {"exploit_name", "tool_used", "payload", "result", "notes"}
    if field not in allowed:
        raise ValueError(f"Invalid exploit field: {field}")
    return _scoped_write("exploits_attempted", exploit_id, sl_no, {field: value})


def edit_summary_risk(sl_no: int, risk_level: str):
    _validated("risk_level", risk_level)
    conn = get_connection()
    try:
        c = conn.cursor()
        c.execute("UPDATE summary SET risk_level = %s WHERE sl_no = %s", (risk_level, sl_no))
        updated = c.rowcount > 0
        if not updated:
            c.execute("SELECT sl_no FROM summary WHERE sl_no = %s", (sl_no,))
            updated = c.fetchone() is not None
        conn.commit()
        return updated
    finally:
        conn.close()


def edit_correction(correction_id: int, field: str, value: str, *, sl_no: int):
    allowed = {"status", "original_text", "corrected_text", "reason"}
    if field not in allowed:
        raise ValueError(f"Invalid correction field: {field}")
    return _scoped_write("corrections", correction_id, sl_no, {field: _validated(field, value)})


def _delete_scoped(table: str, row_id: int, sl_no: int) -> bool:
    if table not in {"fixes", "exploits_attempted", "corrections"}:
        raise ValueError("Invalid table")
    conn = get_connection()
    try:
        c = conn.cursor()
        c.execute(f"DELETE FROM {table} WHERE id = %s AND sl_no = %s", (row_id, sl_no))
        deleted = c.rowcount > 0
        conn.commit()
        return deleted
    finally:
        conn.close()


def delete_vulnerability(vuln_id: int, *, sl_no: int) -> bool:
    """Atomically delete only the current session's finding and all dependent rows."""
    conn = get_connection()
    try:
        c = conn.cursor()
        # Use the same lock order as child inserts: session, then finding.
        # Without this, a correction can be inserted after our ownership
        # check but before the dependent rows are removed.
        _lock_session_writer(c, sl_no)
        c.execute("SELECT id FROM vulnerabilities WHERE id = %s AND sl_no = %s", (vuln_id, sl_no))
        if c.fetchone() is None:
            return False
        for table in ("evaluations", "corrections", "fixes"):
            c.execute(f"DELETE FROM {table} WHERE vuln_id = %s AND sl_no = %s", (vuln_id, sl_no))
        c.execute("DELETE FROM vulnerabilities WHERE id = %s AND sl_no = %s", (vuln_id, sl_no))
        conn.commit()
        return True
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def delete_exploit(exploit_id: int, *, sl_no: int):
    return _delete_scoped("exploits_attempted", exploit_id, sl_no)


def delete_fix(fix_id: int, *, sl_no: int):
    return _delete_scoped("fixes", fix_id, sl_no)


def delete_correction(correction_id: int, *, sl_no: int):
    return _delete_scoped("corrections", correction_id, sl_no)


def delete_full_session(sl_no: int):
    """
    Atomically wipe everything linked to a sl_no across all 7 tables.
    Order matters — delete children before parent (FK constraints).
    """
    conn = get_connection()
    try:
        c = conn.cursor()
        # Take the same session-row lock used by correction/evaluation writers
        # before deleting dependants. In MariaDB this is a row lock; in SQLite
        # it reserves the writer before the first child DELETE.
        _lock_session_writer(c, sl_no)
        c.execute("DELETE FROM evaluations        WHERE sl_no = %s", (sl_no,))
        c.execute("DELETE FROM corrections       WHERE sl_no = %s", (sl_no,))
        c.execute("DELETE FROM fixes             WHERE sl_no = %s", (sl_no,))
        c.execute("DELETE FROM exploits_attempted WHERE sl_no = %s", (sl_no,))
        c.execute("DELETE FROM vulnerabilities   WHERE sl_no = %s", (sl_no,))
        c.execute("DELETE FROM summary           WHERE sl_no = %s", (sl_no,))
        c.execute("DELETE FROM history           WHERE sl_no = %s", (sl_no,))
        conn.commit()
        print(f"[+] Full session SL#{sl_no} deleted from all tables.")
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()


# ─────────────────────────────────────────────
# RE-EXPORTS — split modules, same import paths
# ─────────────────────────────────────────────

_COMPAT_EXPORTS = {
    'export_training_data': 'penx_app.storage.db_training',
    'save_evaluation': 'penx_app.storage.db_evals', 'get_evaluations': 'penx_app.storage.db_evals',
    'delete_evaluation': 'penx_app.storage.db_evals', 'export_eval_package': 'penx_app.storage.db_evals',
    'parse_evaluation_response': 'penx_app.storage.db_evals',
    'print_history': 'penx_app.cli.db_display', 'print_session': 'penx_app.cli.db_display',
}


def __getattr__(name):
    from importlib import import_module
    if name not in _COMPAT_EXPORTS:
        raise AttributeError(name)
    return getattr(import_module(_COMPAT_EXPORTS[name]), name)


# ─────────────────────────────────────────────
# QUICK CONNECTION TEST
# ─────────────────────────────────────────────

if __name__ == "__main__":
    try:
        conn = get_connection()
        print("[+] Database connection successful.")
        from penx_app.config import DB_ENGINE
        print(f"[+] Database backend: {DB_ENGINE}")
        conn.close()
    except Exception as e:
        print(f"[!] Connection failed: {e}")
