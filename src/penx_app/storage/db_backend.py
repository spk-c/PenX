"""Cross-platform database backend (SQLite by default on Windows).

Existing PenX modules use MySQL-style %s parameters. SQLiteCursor adapts them
without altering the application-facing row layout or CRUD APIs.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

from penx_app.config import DB_ENGINE, DB_PATH, DB_HOST, DB_USER, DB_PASSWORD, DB_NAME


# Public tuple layouts must not depend on physical column order: SQLite appends
# migrated columns, whereas new databases create them in the positions below.
VULNERABILITY_COLUMNS = "id, sl_no, vuln_name, severity, confidence, port, service, description"
SUMMARY_COLUMNS = "id, sl_no, raw_scan, ai_analysis, risk_level, model_name, generated_at"
FIX_COLUMNS = "id, sl_no, vuln_id, fix_text, source"
EXPLOIT_COLUMNS = "id, sl_no, exploit_name, tool_used, payload, result, notes"
CORRECTION_COLUMNS = ("id, sl_no, vuln_id, status, original_text, "
                      "corrected_text, reason, corrected_at")
EVALUATION_COLUMNS = ("id, sl_no, vuln_id, evaluator, evidence_cited, verdict, "
                      "confidence, severity_correct, cve_correct, software_correct, "
                      "fix_correct, notes, evaluated_at")


from penx_app.storage.schema_migrations import SCHEMA as SCHEMA, initialize_sqlite


class SQLiteCursor:
    def __init__(self, cursor: sqlite3.Cursor):
        self._cursor = cursor

    def execute(self, query: str, params=()):
        # Parameter placeholders are the only MySQL construct used by CRUD paths.
        self._cursor.execute(query.replace('%s', '?'), params)
        return self

    def fetchone(self):
        return self._cursor.fetchone()

    def fetchall(self):
        return self._cursor.fetchall()

    @property
    def lastrowid(self):
        return self._cursor.lastrowid

    def __getattr__(self, name):
        return getattr(self._cursor, name)


class SQLiteConnection:
    def __init__(self, connection: sqlite3.Connection):
        self._connection = connection

    def cursor(self):
        return SQLiteCursor(self._connection.cursor())

    def commit(self):
        return self._connection.commit()

    def close(self):
        return self._connection.close()

    def __getattr__(self, name):
        return getattr(self._connection, name)


def get_connection():
    """Return MariaDB connector or compatible SQLite connection."""
    if DB_ENGINE == 'mariadb':
        import mysql.connector
        return mysql.connector.connect(
            host=DB_HOST, user=DB_USER, password=DB_PASSWORD, database=DB_NAME
        )
    if DB_ENGINE != 'sqlite':
        raise ValueError('Invalid PENX_DB_ENGINE. Expected sqlite or mariadb.')

    path = Path(DB_PATH).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), timeout=30)
    conn.execute('PRAGMA busy_timeout=30000')
    conn.execute('PRAGMA foreign_keys=ON')
    try:
        initialize_sqlite(conn)
    except BaseException:
        conn.close()
        raise
    return SQLiteConnection(conn)
