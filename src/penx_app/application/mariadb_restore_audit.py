"""Read-only, opt-in MariaDB scratch recovery comparison (PX-004).

Compares the *current* source and scratch schemas, not the historical bytes
in the saved dump. No SQL imports, migrations, DDL or database writes.
"""
from __future__ import annotations

from contextlib import closing
import hashlib
import json
import re
from pathlib import Path

from penx_app.application.evidence_verification import _read_only_mariadb_factory
from penx_app.application.mariadb_backup import _read_manifest
from penx_app.application.mariadb_restore_plan import plan_scratch_restore

_NAME = re.compile(r"[A-Za-z0-9_]{1,64}\Z")
MAX_TABLES = 100


def _bounded_schema_snapshot(
    factory, *, database: str, expected_tables: list[str],
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
            return {
                "tables": names,
                "columns": [list(row) for row in columns],
                "indexes": [list(row) for row in indexes],
                "row_counts": counts,
            }, sum(n for _, n in counts)
        finally:
            cursor.close()


def audit_scratch_restore(
    backup_file: str | Path, *, target_schema: str, host: str, port: int,
    source_user: str, source_password: str,
    target_user: str, target_password: str,
) -> dict:
    """Compare source/scratch under separate mandatory READ ONLY snapshots.

    A matching result is NOT a content-level restore guarantee: source rows
    may have changed since the dump, and two different datasets can have
    the same row counts and schema. This must never authorize an import.
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
        source_factory, database=source, expected_tables=expected)
    target_data, target_rows = _bounded_schema_snapshot(
        target_factory, database=target_schema, expected_tables=expected)
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
        "status": "observed-read-only-structural-parity",
        "backup_sha256": plan["backup_sha256"],
        "plan_sha256": plan["plan_sha256"],
        "source_database": source,
        "target_schema": target_schema,
        "tables_compared": len(expected),
        "rows_counted_per_side": source_rows,
        "scratch_rows_counted": target_rows,
        "structural_sha256": metadata_hash,
        "snapshot_contents_verified": False,
        "historical_backup_rows_verified": False,
        "restore_available": False,
        "sql_executed": False,
        "database_modified": False,
        "note": (
            "Matching live schema and row counts in separate read-only "
            "snapshots is not a byte-perfect restore proof, not a "
            "reservation, and never authorizes SQL import."
        ),
    }
