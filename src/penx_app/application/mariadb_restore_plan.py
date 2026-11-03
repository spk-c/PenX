"""Offline MariaDB scratch restore intent; never executes SQL or connects to DB.

This validates only the backup file's SHA-256/manifest and the proposed
destination name. Database existence, privileges and SQL safety are NOT
checked. No successful result authorizes a restore.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from penx_app.application.mariadb_backup import verify_logical_backup

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
