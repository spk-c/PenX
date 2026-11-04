"""PX-004 offline MariaDB dump red-flag diagnostics, NOT SQL validation.

This is deliberately a conservative, bounded lexical review: the SQL is never
executed or parsed into an executable plan. Absence of recognized red flags
does not imply safe SQL, genuine provenance, or a restorable snapshot.
"""
from __future__ import annotations

import re
from pathlib import Path

from penx_app.application.mariadb_backup import (
    _read_manifest, verify_logical_backup,
)

DIAGNOSTIC_SCHEMA = "penx-mariadb-dump-diagnostic-v1"
MAX_INSPECTION_BYTES = 8 * 1024 * 1024
MAX_LINE_CHARS = 64 * 1024
MAX_LINES = 100_000
_TABLE_DDL = re.compile(
    r"(?im)^\s*CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?"
    r"(?:`([A-Za-z0-9_]{1,64})`|([A-Za-z0-9_]{1,64}))\s*\("
)
_TABLE_INSERT = re.compile(
    r"(?im)^\s*INSERT\s+INTO\s+"
    r"(?:`([A-Za-z0-9_]{1,64})`|([A-Za-z0-9_]{1,64}))(?=\s|\(|;|$)"
)
# Inspect *potentially* executable statements even when not at a line start.
# Quoted data can trigger these expressions: such a result means manual review,
# never proof that malicious SQL would actually execute.
_RISK_PATTERNS = {
    "executable-comment": re.compile(r"/\*!|/\*M!", re.IGNORECASE),
    "block-comment": re.compile(r"/\*(?![!])", re.IGNORECASE),
    "client-delimiter-or-source": re.compile(
        r"(?im)^\s*(?:DELIMITER|SOURCE|\\\.|\\!|SYSTEM)\b"
    ),
    "external-data-access": re.compile(
        r"(?i)\b(?:LOAD\s+DATA|INTO\s+(?:OUTFILE|DUMPFILE))\b"
    ),
    "schema-context-change": re.compile(
        r"(?im)(?:^|;)\s*(?:USE\b|CREATE\s+DATABASE\b|DROP\s+DATABASE\b)"
    ),
    "destructive-or-unexpected-write": re.compile(
        r"(?im)(?:^|;)\s*(?:DROP\s+TABLE|TRUNCATE|ALTER\s+TABLE|"
        r"DELETE\s+FROM|UPDATE\s+|REPLACE\s+INTO)\b"
    ),
    "privilege-or-program-execution": re.compile(
        r"(?im)(?:^|;)\s*(?:GRANT|REVOKE|CREATE\s+(?:USER|FUNCTION|"
        r"PROCEDURE|TRIGGER|EVENT)|CALL|EXECUTE|PREPARE)\b"
    ),
    "session-mode-or-charset-change": re.compile(
        r"(?im)(?:^|;)\s*(?:SET\s+(?:NAMES|SQL_MODE|CHARACTER_SET|"
        r"@@|GLOBAL\b|SESSION\b)|RESET\b)"
    ),
    "cross-schema-identifier": re.compile(
        r"`[A-Za-z0-9_]{1,64}`\s*\.\s*`[A-Za-z0-9_]{1,64}`"
    ),
}
_COMPLETE_MARKER = re.compile(
    r"(?m)^-- Dump completed on \d{4}-\d\d-\d\d\s*$"
)


def inspect_logical_dump(path: str | Path) -> dict:
    """Inspect one hash-bound SQL pair locally and return only generic flags.

    This is *not* an allowlist, SQL parser, restore authorization, or proof of
    harmlessness. Diagnostics are independent of the SHA file identity check.
    The method never contacts MariaDB, uses subprocesses or emits raw SQL.
    """
    verified = verify_logical_backup(path)
    sql = Path(path).with_suffix(".sql")
    # Verify first, then read a bounded amount for the separate diagnostic.
    # Re-reading is not atomic against malicious concurrent file replacement:
    # operator-protected offline copies are still required.
    if verified["size_bytes"] > MAX_INSPECTION_BYTES:
        raise ValueError("SQL diagnostic size budget exceeded")
    with sql.open("rb") as source:
        raw = source.read(MAX_INSPECTION_BYTES + 1)
    if len(raw) > MAX_INSPECTION_BYTES or len(raw) != verified["size_bytes"]:
        raise ValueError("SQL diagnostic source changed or exceeds budget")
    # Reconfirm exact bytes in case an offline file changed after verification.
    import hashlib
    if hashlib.sha256(raw).hexdigest() != verified["sha256"]:
        raise ValueError("SQL diagnostic source changed after verification")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise ValueError("SQL diagnostic requires UTF-8") from exc
    if "\x00" in text or any(
        ord(c) < 32 and c not in "\t\r\n" for c in text
    ):
        raise ValueError("SQL diagnostic rejected binary/control content")
    lines = text.splitlines()
    if len(lines) > MAX_LINES or any(len(line) > MAX_LINE_CHARS for line in lines):
        raise ValueError("SQL diagnostic line budget exceeded")

    manifest = _read_manifest(sql.with_suffix(".json"))
    expected_tables = set(manifest["tables"])
    created: set[str] = set()
    duplicate_create = False
    unknown_tables = False
    insert_before_create = False
    for line in lines:
        create = _TABLE_DDL.match(line)
        if create:
            name = create.group(1) or create.group(2)
            if name is None:
                raise ValueError("Invalid CREATE TABLE identifier")
            if name in created:
                duplicate_create = True
            else:
                created.add(name)
            if name not in expected_tables:
                unknown_tables = True
        insertion = _TABLE_INSERT.match(line)
        if insertion:
            name = insertion.group(1) or insertion.group(2)
            if name is None:
                raise ValueError("Invalid INSERT target")
            if name not in expected_tables:
                unknown_tables = True
            if name not in created:
                insert_before_create = True

    flags = {name for name, pattern in _RISK_PATTERNS.items()
             if pattern.search(text)}
    if duplicate_create:
        flags.add("duplicate-create-table")
    if unknown_tables:
        flags.add("table-not-in-manifest")
    if insert_before_create:
        flags.add("insert-before-create")
    if created != expected_tables:
        flags.add("missing-table-creation")
    # MariaDB --skip-comments can deliberately omit this footer. Its absence
    # is uncertain provenance/completeness, NOT definitive proof of truncation.
    if not _COMPLETE_MARKER.search(text):
        flags.add("completion-marker-not-observed")
    # Any tokens that evade these checks remain untrusted by design.
    return {
        "schema": DIAGNOSTIC_SCHEMA,
        "status": "manual-review-required",
        "backup_sha256": verified["sha256"],
        "inspected_bytes": len(raw),
        "manifest_table_count": len(expected_tables),
        "observed_create_table_count": len(created),
        "risk_flags": sorted(flags),
        "sql_semantics_verified": False,
        "historical_backup_rows_verified": False,
        "sql_executed": False,
        "restore_available": False,
        "limitations": "Lexical heuristics only; no statement parser, provenance attestation or approval to import SQL.",
    }
