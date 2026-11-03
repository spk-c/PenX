"""Offline MariaDB scratch restore intent; never executes SQL or connects to DB.

This validates only the backup file's SHA-256/manifest and the proposed
destination name. Database existence, privileges and SQL safety are NOT
checked. No successful result authorizes a restore.
"""
from __future__ import annotations

from contextlib import closing
import hashlib
import json
import re
from pathlib import Path

from penx_app.application.mariadb_backup import verify_logical_backup
from penx_app.application.evidence_verification import _read_only_mariadb_factory

PLAN_SCHEMA = "penx-mariadb-restore-plan-v1"
_SCRATCH = re.compile(r"penx_restore_[a-f0-9]{32}\Z")


def plan_scratch_restore(
    backup_file: str | Path, *, target_schema: str,
) -> dict:
    """Make a deterministic, non-executable recovery plan.

    Even a valid backup manifest does not prove the SQL is harmless.
    """
    if not isinstance(target_schema, str) or not _SCRATCH.fullmatch(
        target_schema
    ):
        raise ValueError("Proposed target must be penx_restore_<32 hex>")
    info = verify_logical_backup(backup_file)
    if info["source_database"].casefold() == target_schema.casefold():
        raise ValueError("Refusing to plan a source-database overwrite")
    identity = {
        "schema": PLAN_SCHEMA,
        "backup_sha256": info["sha256"],
        "backup_size_bytes": info["size_bytes"],
        "source_database": info["source_database"],
        "target_schema": target_schema,
    }
    canonical = json.dumps(
        identity, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")
    return {
        **identity,
        "status": "read-only-plan",
        "plan_sha256": hashlib.sha256(canonical).hexdigest(),
        "backup_file": info["file"],
        "backup_integrity": "local-file-hash-matches-manifest",
        "target_existence": "not-checked",
        "target_must_be_new_and_empty": True,
        "separate_target_scoped_account_required": True,
        "production_pre_restore_backup_required": True,
        "maintenance_and_rollback_not_verified": True,
        "sql_semantics_verified": False,
        "restore_available": False,
        "sql_executed": False,
        "note": (
            "Offline intent only: no server access, SQL execution or "
            "target validation. A matching hash is not an SQL audit "
            "or approval to overwrite any database."
        ),
    }


# MariaDB information_schema is privilege-filtered. An absent row does NOT
# establish that a schema is free unless the current user can enumerate all
# schema names. Require a direct global SHOW DATABASES grant; do not
# incorrectly infer it from SELECT rights or implicit role grants.
_GLOBAL_GRANT = re.compile(
    r"^GRANT\s+(.+?)\s+ON\s+\*\.\*\s+TO\s+",
    re.IGNORECASE,
)


def _has_explicit_schema_visibility(grants: object) -> bool:
    if not isinstance(grants, (list, tuple)):
        return False
    for row in grants:
        if not isinstance(row, (tuple, list)) or len(row) != 1:
            continue
        statement = row[0]
        if not isinstance(statement, str):
            continue
        match = _GLOBAL_GRANT.match(statement.strip())
        if not match:
            continue
        privileges = [part.strip().upper()
                      for part in match.group(1).split(",")]
        if "SHOW DATABASES" in privileges:
            return True
    return False


def preflight_scratch_target(
    backup_file: str | Path, *, target_schema: str, host: str,
    port: int, database: str, user: str, password: str,
) -> dict:
    """Check scratch name absence in one mandatory READ ONLY DB snapshot.

    This is NOT a reservation: the schema might appear immediately afterward.
    No DDL, SQL import, privilege change, or target creation is possible here.
    Only a visibility-proven *current snapshot* can report absent.
    """
    plan = plan_scratch_restore(
        backup_file, target_schema=target_schema)
    if database != plan["source_database"]:
        raise ValueError("Read-only login schema differs from the backup source")
    # The connection must enter server-enforced READ ONLY before any SELECT.
    factory = _read_only_mariadb_factory(host, port, database, user, password)
    with closing(factory()) as connection:
        cursor = connection.cursor()
        try:
            cursor.execute("SHOW GRANTS")
            grants = cursor.fetchall()
            if not _has_explicit_schema_visibility(grants):
                raise ValueError("Schema visibility is not proven")
            cursor.execute(
                "SELECT SCHEMA_NAME FROM information_schema.SCHEMATA "
                "WHERE LOWER(SCHEMA_NAME) = LOWER(%s)",
                (target_schema,),
            )
            names = cursor.fetchall()
            if not isinstance(names, (list, tuple)):
                raise ValueError("Scratch target visibility query was incomplete")
            if names:
                raise ValueError("Scratch target already exists")
        finally:
            cursor.close()
    return {
        **plan,
        "status": "read-only-server-preflight",
        "target_existence": "absent-at-check-time-only",
        "schema_visibility": "explicit-global-show-databases",
        "server_snapshot_checked": True,
        "target_reserved": False,
        "restore_available": False,
        "sql_executed": False,
        "note": (
            "Snapshot-only target absence checked without DDL or import. "
            "The name is not reserved and may exist later; all conditions "
            "must be rechecked at an independently approved execution gate."
        ),
    }
