"""Transactional, fail-closed SQLite migrations; MariaDB DDL is manual."""
SCHEMA = """
CREATE TABLE IF NOT EXISTS history (
    sl_no INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    scan_date TEXT NOT NULL,
    status TEXT DEFAULT 'active'
);
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sl_no INTEGER,
    vuln_name TEXT,
    severity TEXT,
    confidence TEXT DEFAULT 'possible',
    port TEXT,
    service TEXT,
    description TEXT,
    FOREIGN KEY(sl_no) REFERENCES history(sl_no)
);
CREATE TABLE IF NOT EXISTS fixes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sl_no INTEGER,
    vuln_id INTEGER,
    fix_text TEXT,
    source TEXT,
    FOREIGN KEY(sl_no) REFERENCES history(sl_no),
    FOREIGN KEY(vuln_id) REFERENCES vulnerabilities(id)
);
CREATE TABLE IF NOT EXISTS exploits_attempted (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sl_no INTEGER,
    exploit_name TEXT,
    tool_used TEXT,
    payload TEXT,
    result TEXT,
    notes TEXT,
    FOREIGN KEY(sl_no) REFERENCES history(sl_no)
);
CREATE TABLE IF NOT EXISTS summary (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sl_no INTEGER,
    raw_scan TEXT,
    ai_analysis TEXT,
    risk_level TEXT,
    model_name TEXT DEFAULT '',
    generated_at TEXT,
    FOREIGN KEY(sl_no) REFERENCES history(sl_no)
);
CREATE TABLE IF NOT EXISTS corrections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sl_no INTEGER NOT NULL,
    vuln_id INTEGER NOT NULL,
    status TEXT NOT NULL,
    original_text TEXT,
    corrected_text TEXT,
    reason TEXT,
    corrected_at TEXT NOT NULL,
    FOREIGN KEY(sl_no) REFERENCES history(sl_no),
    FOREIGN KEY(vuln_id) REFERENCES vulnerabilities(id)
);
CREATE TABLE IF NOT EXISTS evaluations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sl_no INTEGER NOT NULL,
    vuln_id INTEGER NOT NULL,
    evaluator TEXT NOT NULL,
    evidence_cited TEXT,
    verdict TEXT NOT NULL,
    confidence TEXT DEFAULT 'medium',
    severity_correct INTEGER DEFAULT 0,
    cve_correct INTEGER DEFAULT 0,
    software_correct INTEGER DEFAULT 0,
    fix_correct INTEGER DEFAULT 0,
    notes TEXT,
    evaluated_at TEXT NOT NULL,
    FOREIGN KEY(sl_no) REFERENCES history(sl_no),
    FOREIGN KEY(vuln_id) REFERENCES vulnerabilities(id)
);
CREATE TABLE IF NOT EXISTS learned_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_text TEXT NOT NULL,
    source TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""


SCHEMA_VERSION = 3


def _check_summary_integrity(conn):
    """Refuse unsafe upgrades rather than guessing which historical row to keep.

    Only session identifiers are inspected; raw scans and AI text are never
    copied, deleted or included in diagnostic messages.
    """
    null_row = conn.execute(
        "SELECT id FROM summary WHERE sl_no IS NULL LIMIT 1"
    ).fetchone()
    if null_row:
        raise ValueError(
            "SQLite migration v3 blocked: summary row has a NULL session ID "
            f"(summary.id={null_row[0]}). Back up and audit the database with "
            "scripts/audit_summary_uniqueness.py before correcting legacy data."
        )
    duplicate = conn.execute(
        "SELECT sl_no, COUNT(*) FROM summary GROUP BY sl_no "
        "HAVING COUNT(*) > 1 LIMIT 1"
    ).fetchone()
    if duplicate:
        raise ValueError(
            "SQLite migration v3 blocked: duplicate summary rows for "
            f"session {duplicate[0]} ({duplicate[1]} rows). No rows were "
            "removed. Back up and audit using scripts/audit_summary_uniqueness.py."
        )
    orphan = conn.execute(
        "SELECT s.id, s.sl_no FROM summary AS s LEFT JOIN history AS h "
        "ON h.sl_no = s.sl_no WHERE h.sl_no IS NULL LIMIT 1"
    ).fetchone()
    if orphan:
        raise ValueError(
            "SQLite migration v3 blocked: orphan summary "
            f"id={orphan[0]}, session={orphan[1]}. No rows were removed. "
            "Back up and audit using scripts/audit_summary_uniqueness.py."
        )


def initialize_sqlite(conn):
    """Upgrade SQLite in one transaction; preserve all legacy rows on failure."""
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    if version > SCHEMA_VERSION:
        raise ValueError(
            f"Unsupported database schema version {version}; update PenX before opening it."
        )
    if version == SCHEMA_VERSION:
        return
    try:
        if version < 2:
            # executescript commits an open transaction: BEGIN must be in the
            # script so the entire baseline/legacy column upgrade is atomic.
            conn.executescript("BEGIN IMMEDIATE;\n" + SCHEMA)
            additions = (
                ('vulnerabilities', 'confidence', "TEXT DEFAULT 'possible'"),
                ("summary", "model_name", "TEXT DEFAULT ''"),
                ("history", "status", "TEXT DEFAULT 'active'"),
                ("summary", "scan_metadata", "TEXT DEFAULT ''"),
            )
            for table, column, declaration in additions:
                existing = {
                    row[1] for row in conn.execute(f"PRAGMA table_info({table})")
                }
                if column not in existing:
                    conn.execute(
                        f"ALTER TABLE {table} ADD COLUMN {column} {declaration}"
                    )
        else:
            # Lock writers before auditing, so no new duplicates can appear
            # between preflight and index creation.
            conn.execute("BEGIN IMMEDIATE")

        _check_summary_integrity(conn)
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_summary_sl_no "
            "ON summary (sl_no)"
        )
        # Historical SQLite schema allows NULL; UNIQUE indexes alone permit
        # multiple NULLs. These triggers also enforce the parent-session
        # reference when an external SQLite client disabled foreign_keys.
        for operation in ("INSERT", "UPDATE OF sl_no"):
            name = ("insert" if operation == "INSERT" else "update")
            conn.execute(
                f"CREATE TRIGGER IF NOT EXISTS trg_summary_session_{name} "
                f"BEFORE {operation} ON summary "
                "WHEN NEW.sl_no IS NULL OR NOT EXISTS "
                "(SELECT 1 FROM history WHERE sl_no = NEW.sl_no) "
                "BEGIN SELECT RAISE(ABORT, "
                "'summary.sl_no must reference an existing session'); END"
            )
        conn.execute("PRAGMA user_version=3")
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
