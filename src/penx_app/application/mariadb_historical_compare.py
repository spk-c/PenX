"""Offline PX-004 comparison of externally recorded historical vs scratch fingerprints.

This does not read a database, execute SQL, authenticate an evidence producer,
or approve a restore. A matching operator-supplied SHA-256 pin authenticates
bytes only against that separately retained value, not their historical origin.
"""
from __future__ import annotations

from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import stat

SCHEMA = "penx-mariadb-content-evidence-v1"
MAX_RECORD_BYTES = 64 * 1024
MAX_TABLES = 100
MAX_ROWS_PER_TABLE = 2000
MAX_ROWS_TOTAL = 10000
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_NAME = re.compile(r"[A-Za-z0-9_]{1,64}\Z")
_UTC = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ\Z")


def _strict_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate evidence JSON field")
        result[key] = value
    return result


def _reject_constant(value: str):
    raise ValueError("Non-finite evidence JSON number")


def _sha256(value: object) -> bool:
    return type(value) is str and _HEX.fullmatch(value) is not None


def _read_record(path: str | Path) -> tuple[dict, str]:
    """Bound reads and refuse symlinks; never access database or dump bytes."""
    path = Path(path)
    if path.is_symlink():
        raise ValueError("Evidence symlink refused")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(path, flags), "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_RECORD_BYTES:
            raise ValueError("Evidence file size/type refused")
        data = handle.read(MAX_RECORD_BYTES + 1)
        if len(data) != info.st_size or path.is_symlink():
            raise ValueError("Evidence changed while reading")
    digest = hashlib.sha256(data).hexdigest()
    try:
        record = json.loads(data.decode("utf-8"), object_pairs_hook=_strict_object,
                            parse_constant=_reject_constant)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise ValueError("Malformed evidence record") from exc
    if not isinstance(record, dict) or set(record) != {
            "schema", "role", "database", "observed_at", "dump_sha256",
            "structure_sha256", "tables"}:
        raise ValueError("Unexpected evidence record fields")
    if (record["schema"] != SCHEMA or type(record["role"]) is not str
            or record["role"] not in {"source", "scratch"}):
        raise ValueError("Invalid evidence schema/role")
    if type(record["database"]) is not str or not _NAME.fullmatch(record["database"]):
        raise ValueError("Invalid evidence database")
    if not _sha256(record["dump_sha256"]) or not _sha256(record["structure_sha256"]):
        raise ValueError("Invalid evidence digest")
    date = record["observed_at"]
    if type(date) is not str or not _UTC.fullmatch(date):
        raise ValueError("Invalid evidence timestamp")
    try:
        datetime.strptime(date, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise ValueError("Invalid evidence calendar date") from exc
    rows = record["tables"]
    if not isinstance(rows, list) or not 0 < len(rows) <= MAX_TABLES:
        raise ValueError("Invalid evidence table count")
    names = set()
    total = 0
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"name", "rows", "content_sha256"}:
            raise ValueError("Invalid evidence table fields")
        name = row["name"]
        if type(name) is not str or not _NAME.fullmatch(name) or name in names:
            raise ValueError("Invalid or duplicate evidence table")
        names.add(name)
        if type(row["rows"]) is not int or not 0 <= row["rows"] <= MAX_ROWS_PER_TABLE:
            raise ValueError("Unbounded evidence row count")
        if not _sha256(row["content_sha256"]):
            raise ValueError("Invalid content fingerprint")
        total += row["rows"]
        if total > MAX_ROWS_TOTAL:
            raise ValueError("Evidence row budget exceeded")
    return record, digest


def compare_historical_evidence(
    source_path: str | Path, scratch_path: str | Path, *,
    expected_source_record_sha256: str, expected_dump_sha256: str,
    source_database: str, scratch_database: str,
) -> dict:
    """Compare bounded metadata only; an operator must independently authenticate
    the source capture and a separate, isolated scratch import.

    Uses the table fingerprints from mariadb_restore_audit._content_fingerprint.
    No match can prove the dump originated at that historical source instant.
    """
    if not _sha256(expected_source_record_sha256) or not _sha256(expected_dump_sha256):
        raise ValueError("Expected digests must be lowercase SHA-256")
    if not isinstance(source_database, str) or not _NAME.fullmatch(source_database):
        raise ValueError("Invalid expected source database")
    if not isinstance(scratch_database, str) or not _NAME.fullmatch(scratch_database):
        raise ValueError("Invalid expected scratch database")
    if source_database == scratch_database:
        raise ValueError("Scratch database must differ from source")
    if Path(source_path).resolve() == Path(scratch_path).resolve():
        raise ValueError("Source and scratch evidence must be different files")
    source, digest = _read_record(source_path)
    if digest != expected_source_record_sha256:
        raise ValueError("Independent source evidence pin mismatch")
    scratch, _ = _read_record(scratch_path)
    if (source["role"] != "source" or scratch["role"] != "scratch"
            or source["database"] != source_database
            or scratch["database"] != scratch_database):
        raise ValueError("Evidence stage or database mismatch")
    if (source["dump_sha256"] != expected_dump_sha256
            or scratch["dump_sha256"] != expected_dump_sha256):
        raise ValueError("Evidence dump binding mismatch")
    if scratch["observed_at"] < source["observed_at"]:
        raise ValueError("Scratch observation predates source evidence")
    if (source["structure_sha256"] != scratch["structure_sha256"]
            or {row["name"]: (row["rows"], row["content_sha256"])
                for row in source["tables"]}
            != {row["name"]: (row["rows"], row["content_sha256"])
                for row in scratch["tables"]}):
        raise ValueError("Historical and scratch fingerprints differ")
    return {
        "status": "offline-record-fingerprint-match-only",
        "source_record_sha256": digest,
        "dump_sha256": expected_dump_sha256,
        "tables_compared": len(source["tables"]),
        "rows_compared": sum(row["rows"] for row in source["tables"]),
        "source_observed_at": source["observed_at"],
        "scratch_observed_at": scratch["observed_at"],
        "historical_source_authenticated": False,
        "historical_backup_rows_verified": False,
        "sql_semantics_verified": False,
        "restore_available": False,
        "sql_executed": False,
        "database_modified": False,
    }
