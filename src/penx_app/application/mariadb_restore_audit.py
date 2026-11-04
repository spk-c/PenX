"""Read-only, opt-in MariaDB scratch recovery comparison (PX-004).

Compares the *current* source and scratch schemas, not the historical bytes
in the saved dump. No SQL imports, migrations, DDL or database writes.
"""
from __future__ import annotations

from contextlib import closing
from datetime import date, datetime, time, timedelta
from decimal import Decimal
import hashlib
import math
import json
import re
from pathlib import Path

from penx_app.application.evidence_verification import _read_only_mariadb_factory
from penx_app.application.mariadb_backup import _read_manifest
from penx_app.application.mariadb_restore_plan import plan_scratch_restore

_NAME = re.compile(r"[A-Za-z0-9_]{1,64}\Z")
MAX_TABLES = 100
MAX_CONTENT_ROWS_PER_TABLE = 2000
MAX_CONTENT_ROWS_TOTAL = 10000
MAX_CONTENT_CELL_BYTES = 256 * 1024
MAX_CONTENT_ROW_BYTES = 512 * 1024
MAX_CONTENT_BYTES_TOTAL = 32 * 1024 * 1024




def _canonical_cell(value) -> tuple[bytes, bytes]:
    """Canonical and type-separated *in-memory* value encoding.

    Use only supported built-in MariaDB connector conversions, not repr()
    of user objects or locale-dependent text. Unknown/nonfinite values
    fail closed rather than being silently rounded/coerced.
    """
    if value is None:
        return b"null", b""
    if isinstance(value, bool):
        return b"bool", b"1" if value else b"0"
    if isinstance(value, int):
        return b"int", str(value).encode("ascii")
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise ValueError("Unsupported MariaDB decimal content")
        return b"decimal", format(value, "f").encode("ascii")
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("Unsupported MariaDB floating content")
        return b"float", value.hex().encode("ascii")
    if isinstance(value, str):
        # Each Unicode code point needs at least one UTF-8 byte; avoid
        # materializing a second giant allocation for oversized text.
        if len(value) > MAX_CONTENT_CELL_BYTES:
            raise ValueError("Content field exceeds verification budget")
        return b"text", value.encode("utf-8", errors="strict")
    if isinstance(value, (bytes, bytearray, memoryview)):
        if len(value) > MAX_CONTENT_CELL_BYTES:
            raise ValueError("Content field exceeds verification budget")
        return b"bytes", bytes(value)
    if isinstance(value, datetime):
        return b"datetime", value.isoformat(timespec="microseconds").encode("ascii")
    if isinstance(value, date):
        return b"date", value.isoformat().encode("ascii")
    if isinstance(value, time):
        return b"time", value.isoformat(timespec="microseconds").encode("ascii")
    if isinstance(value, timedelta):
        # MariaDB TIME can be outside clock range and is decoded as timedelta.
        return b"duration_us", str((value.days * 86400 + value.seconds)
                                    * 1000000 + value.microseconds).encode("ascii")
    raise ValueError("Unsupported MariaDB value type")


def _content_fingerprint(
    cursor, *, database: str, table: str, count: int,
    column_count: int, budget: dict,
) -> str:
    """Order-independent *multiset* fingerprint, bounded in memory.

    Sorted row SHA digests preserve duplicate row multiplicities and avoid
    relying on implicit SQL row order. No values or per-row digests leave
    this process; this is NOT proof against adversarial hash collisions.
    """
    if count > MAX_CONTENT_ROWS_PER_TABLE:
        raise ValueError("Content verification table row budget exceeded")
    cursor.execute(f"SELECT * FROM \x60{database}\x60.\x60{table}\x60")
    row_hashes = []
    for _ in range(count):
        row = cursor.fetchone()
        if not isinstance(row, (tuple, list)) or len(row) != column_count:
            raise ValueError("Content row shape differs from schema")
        row_digest = hashlib.sha256(b"penx-mariadb-row-v1\0")
        row_bytes = 0
        for value in row:
            tag, encoded = _canonical_cell(value)
            if len(encoded) > MAX_CONTENT_CELL_BYTES:
                raise ValueError("Content field exceeds verification budget")
            row_bytes += len(encoded)
            if row_bytes > MAX_CONTENT_ROW_BYTES:
                raise ValueError("Content row exceeds verification budget")
            row_digest.update(len(tag).to_bytes(1, "big"))
            row_digest.update(tag)
            row_digest.update(len(encoded).to_bytes(8, "big"))
            row_digest.update(encoded)
        budget["bytes"] += row_bytes
        if budget["bytes"] > MAX_CONTENT_BYTES_TOTAL:
            raise ValueError("Content bytes exceed verification budget")
        row_hashes.append(row_digest.digest())
    if cursor.fetchone() is not None:
        raise ValueError("Content row count changed during read")
    row_hashes.sort()
    table_digest = hashlib.sha256(b"penx-mariadb-multiset-v1\0")
    table_digest.update(count.to_bytes(8, "big"))
    for item in row_hashes:
        table_digest.update(item)
    return table_digest.hexdigest()


def _bounded_schema_snapshot(
    factory, *, database: str, expected_tables: list[str],
    include_content: bool = False,
) -> tuple[dict, int]:
    """Use an already READ ONLY transaction; never expose raw row contents."""
    with closing(factory()) as conn:
        cursor = conn.cursor()
        try:
            cursor.execute(
                "SELECT TABLE_NAME, ENGINE FROM information_schema.TABLES "
                "WHERE TABLE_SCHEMA=%s AND TABLE_TYPE='BASE TABLE' "
                "ORDER BY TABLE_NAME",
                (database,),
            )
            tables = cursor.fetchall()
            if not isinstance(tables, (list, tuple)):
                raise ValueError("Invalid schema table metadata")
            if len(tables) > MAX_TABLES or any(
                not isinstance(r, (tuple, list)) or len(r) != 2
                or not isinstance(r[0], str) or not _NAME.fullmatch(r[0])
                or r[1] != "InnoDB" for r in tables
            ):
                raise ValueError("Unknown or unsupported MariaDB table")
            names = sorted(r[0] for r in tables)
            if names != expected_tables:
                raise ValueError("PenX table list differs from backup manifest")
            cursor.execute(
                "SELECT TABLE_NAME, ORDINAL_POSITION, COLUMN_NAME, "
                "COLUMN_TYPE, IS_NULLABLE, COLUMN_DEFAULT, EXTRA, "
                "CHARACTER_SET_NAME, COLLATION_NAME "
                "FROM information_schema.COLUMNS WHERE TABLE_SCHEMA=%s "
                "ORDER BY TABLE_NAME, ORDINAL_POSITION",
                (database,),
            )
            columns = cursor.fetchall()
            cursor.execute(
                "SELECT TABLE_NAME, INDEX_NAME, NON_UNIQUE, SEQ_IN_INDEX, "
                "COLUMN_NAME, SUB_PART, INDEX_TYPE "
                "FROM information_schema.STATISTICS WHERE TABLE_SCHEMA=%s "
                "ORDER BY TABLE_NAME, INDEX_NAME, SEQ_IN_INDEX",
                (database,),
            )
            indexes = cursor.fetchall()
            if not isinstance(columns, (list, tuple)) or not isinstance(
                indexes, (list, tuple)
            ):
                raise ValueError("Incomplete MariaDB structural metadata")
            if len(columns) > 3000 or len(indexes) > 3000:
                raise ValueError("Schema metadata exceeds limits")
            # Each table must have at least one readable column.
            if set(row[0] for row in columns) != set(names):
                raise ValueError("Missing MariaDB table column definitions")
            counts = []
            for name in names:
                # Both identifiers were schema-validated, and parameterizing
                # identifiers is unsupported by MariaDB connectors.
                cursor.execute(f"SELECT COUNT(*) FROM "
                               f"\x60{database}\x60.\x60{name}\x60")
                row = cursor.fetchone()
                if (not isinstance(row, (list, tuple)) or len(row) != 1
                        or type(row[0]) is not int or row[0] < 0):
                    raise ValueError("Unable to count MariaDB table rows")
                counts.append((name, row[0]))
            total = sum(n for _, n in counts)
            observation = {
                "tables": names,
                "columns": [list(row) for row in columns],
                "indexes": [list(row) for row in indexes],
                "row_counts": counts,
            }
            if include_content:
                if total > MAX_CONTENT_ROWS_TOTAL:
                    raise ValueError("Content total row budget exceeded")
                columns_by_table = {name: 0 for name in names}
                for col in columns:
                    columns_by_table[col[0]] += 1
                budget = {"bytes": 0}
                observation["content_fingerprints"] = [
                    (name, _content_fingerprint(
                        cursor, database=database, table=name, count=n,
                        column_count=columns_by_table[name], budget=budget,
                    ))
                    for name, n in counts
                ]
            return observation, total
        finally:
            cursor.close()


def audit_scratch_restore(
    backup_file: str | Path, *, target_schema: str, host: str, port: int,
    source_user: str, source_password: str,
    target_user: str, target_password: str,
    verify_content: bool = False,
) -> dict:
    """Compare source/scratch under separate mandatory READ ONLY snapshots.

    Optional bounded row hashes compare *current observed* row multisets.
    Source rows may have changed since the dump. No result authorizes import.
    """
    plan = plan_scratch_restore(backup_file, target_schema=target_schema)
    backup = Path(backup_file)
    manifest = _read_manifest(backup.with_suffix(".json"))
    expected = manifest["tables"]
    if manifest["source_database"] != plan["source_database"]:
        raise ValueError("Backup manifest changed during audit")
    if not isinstance(expected, list) or not expected or len(expected) > MAX_TABLES:
        raise ValueError("Invalid expected MariaDB table inventory")
    source = plan["source_database"]
    if not _NAME.fullmatch(source) or not _NAME.fullmatch(target_schema):
        raise ValueError("Invalid MariaDB database identifiers")

    # The connector enforces loopback and read-only transaction BEFORE
    # any SQL. A schema may be visible/modified between two snapshots;
    # results explicitly are a read-only observation, not a reservation.
    source_factory = _read_only_mariadb_factory(
        host, port, source, source_user, source_password)
    target_factory = _read_only_mariadb_factory(
        host, port, target_schema, target_user, target_password)
    source_data, source_rows = _bounded_schema_snapshot(
        source_factory, database=source, expected_tables=expected,
        include_content=verify_content)
    target_data, target_rows = _bounded_schema_snapshot(
        target_factory, database=target_schema, expected_tables=expected,
        include_content=verify_content)
    if source_data != target_data:
        raise ValueError("Source and scratch differ in schema or row counts")
    # Catch normal accidental changes to the saved dump/manifest during
    # this read-only audit, which can span two separate database snapshots.
    final_plan = plan_scratch_restore(
        backup_file, target_schema=target_schema)
    if final_plan["plan_sha256"] != plan["plan_sha256"]:
        raise ValueError("Backup changed during audit")
    structural = {
        "tables": source_data["tables"],
        "columns": source_data["columns"],
        "indexes": source_data["indexes"],
    }
    metadata_hash = hashlib.sha256(
        json.dumps(structural, sort_keys=True, default=str,
                   separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {
        "status": ("observed-read-only-content-parity" if verify_content
                   else "observed-read-only-structural-parity"),
        "backup_sha256": plan["backup_sha256"],
        "plan_sha256": plan["plan_sha256"],
        "source_database": source,
        "target_schema": target_schema,
        "tables_compared": len(expected),
        "rows_counted_per_side": source_rows,
        "scratch_rows_counted": target_rows,
        "structural_sha256": metadata_hash,
        "snapshot_contents_verified": False,
        "current_row_multiset_compared": verify_content,
        "row_digests_exposed": False,
        "content_limit_rows_per_table": (
            MAX_CONTENT_ROWS_PER_TABLE if verify_content else None),
        "content_limit_rows_total": (
            MAX_CONTENT_ROWS_TOTAL if verify_content else None),
        "historical_backup_rows_verified": False,
        "restore_available": False,
        "sql_executed": False,
        "database_modified": False,
        "note": (
            "Matching current live schema and optional bounded row "
            "content in separate read-only snapshots is not a historical "
            "backup restore proof or authorization to import SQL."
        ),
    }
