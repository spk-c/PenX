"""PX-004: conservative, opt-in MariaDB logical backup and offline hash checks.

This module intentionally has NO restore-to-live-database function. Hashes
prove file identity, not the validity of executable SQL or its provenance.
"""
from __future__ import annotations

from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import uuid

from penx_app.application.evidence_verification import _read_only_mariadb_factory

SCHEMA = "penx-mariadb-logical-v1"
MAX_DUMP_BYTES = 512 * 1024 * 1024
MAX_MANIFEST_BYTES = 16 * 1024
REQUIRED_TABLES = frozenset({
    "history", "summary", "vulnerabilities", "fixes",
    "exploits_attempted", "corrections", "evaluations",
})
_NAME = re.compile(r"^[A-Za-z0-9_]{1,64}$")
_SHA = re.compile(r"^[a-f0-9]{64}$")


def _strict_json(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate metadata field")
        result[key] = value
    return result


def _read_manifest(path: Path) -> dict:
    if path.is_symlink() or not path.is_file():
        raise ValueError("Not a regular manifest file")
    with path.open("rb") as handle:
        data = handle.read(MAX_MANIFEST_BYTES + 1)
    if len(data) > MAX_MANIFEST_BYTES:
        raise ValueError("Manifest too large")
    manifest = json.loads(data.decode("utf-8"), object_pairs_hook=_strict_json)
    if not isinstance(manifest, dict) or set(manifest) != {
            "schema", "status", "file", "source_database", "tables",
            "created_at", "size_bytes", "sha256", "capture_method"}:
        raise ValueError("Unsupported MariaDB backup manifest")
    tables = manifest["tables"]
    if (manifest["schema"] != SCHEMA
            or manifest["status"] != "complete-hash-verified"
            or manifest["capture_method"] != "mariadb-dump-single-transaction-innodb"
            or not isinstance(manifest["file"], str)
            or not re.fullmatch(r"penx-mariadb-[0-9]{8}T[0-9]{6}Z-[a-f0-9]{32}\.sql",
                                manifest["file"])
            or not isinstance(manifest["source_database"], str)
            or not _NAME.fullmatch(manifest["source_database"])
            or not isinstance(tables, list) or len(tables) > 100
            or any(not isinstance(t, str) or not _NAME.fullmatch(t)
                   for t in tables) or tables != sorted(set(tables))
            or not REQUIRED_TABLES.issubset(tables)
            or not isinstance(manifest["created_at"], str)
            or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ",
                                manifest["created_at"])
            or type(manifest["size_bytes"]) is not int
            or not 0 < manifest["size_bytes"] <= MAX_DUMP_BYTES
            or not isinstance(manifest["sha256"], str)
            or not _SHA.fullmatch(manifest["sha256"])):
        raise ValueError("Invalid MariaDB backup metadata")
    return manifest


def verify_logical_backup(path: str | Path) -> dict:
    """Offline-only file identity and metadata check. Does not execute SQL."""
    item = Path(path)
    if item.suffix not in {".sql", ".json"}:
        raise ValueError("Pass an explicit .sql or .json backup path")
    sql = item.with_suffix(".sql")
    meta = item.with_suffix(".json")
    manifest = _read_manifest(meta)
    if manifest["file"] != sql.name or sql.is_symlink() or not sql.is_file():
        raise ValueError("SQL backup file missing, linked or mismatched")
    digest = hashlib.sha256()
    size = 0
    with sql.open("rb") as stream:
        for part in iter(lambda: stream.read(1024 * 1024), b""):
            size += len(part)
            if size > MAX_DUMP_BYTES:
                raise ValueError("SQL backup exceeds limit")
            digest.update(part)
    if size != manifest["size_bytes"] or digest.hexdigest() != manifest["sha256"]:
        raise ValueError("SQL backup SHA-256/size mismatch")
    return {
        "status": "verified-file-integrity-only",
        "file": sql.name,
        "source_database": manifest["source_database"],
        "tables_in_manifest": len(manifest["tables"]),
        "size_bytes": size,
        "sha256": digest.hexdigest(),
        "sql_semantics_verified": False,
    }


def preview_logical_backup(path: str | Path) -> dict:
    """Read-only preview; no SQL parser, target connection, or restoration."""
    result = verify_logical_backup(path)
    return {
        **result,
        "restore_available": False,
        "note": "Hash and metadata verified only; restore to a live MariaDB database is not implemented. Test restoration requires a separately isolated empty database and operator review.",
    }


def _source_tables(host: str, port: int, database: str,
                   user: str, password: str) -> list[str]:
    factory = _read_only_mariadb_factory(host, port, database, user, password)
    with closing(factory()) as conn:
        cursor = conn.cursor()
        try:
            cursor.execute(
                "SELECT TABLE_NAME, ENGINE FROM information_schema.TABLES "
                "WHERE TABLE_SCHEMA=%s AND TABLE_TYPE='BASE TABLE'",
                (database,),
            )
            rows = cursor.fetchall()
        finally:
            cursor.close()
    if (len(rows) > 100
            or any(not isinstance(name, str) or not _NAME.fullmatch(name)
                   or engine != "InnoDB" for name, engine in rows)):
        raise ValueError("MariaDB backup requires bounded InnoDB tables only")
    tables = sorted(name for name, _ in rows)
    if len(tables) != len(set(tables)) or not REQUIRED_TABLES.issubset(tables):
        raise ValueError("MariaDB schema missing required PenX tables")
    return tables


def create_logical_backup(
    *, host: str, port: int, database: str, user: str, password: str,
    directory: str | Path, executable: str = "mariadb-dump",
) -> dict:
    """Dump one explicit local PenX schema; only publish verified file pairs.

    This uses the MariaDB dump client with shell=False, never puts the
    password on argv, and suppresses stderr to avoid credential disclosure.
    A successful dump is NOT equivalent to a tested, restorable snapshot.
    """
    if not executable or Path(executable).name not in {
            "mariadb-dump", "mariadb-dump.exe"}:
        raise ValueError("Unexpected MariaDB dump executable")
    target = Path(directory)
    if target.is_symlink() or not target.is_dir():
        raise ValueError("Backup output must be an existing real directory")
    # Validate host and account before opening files or launching the client.
    # The same checks run again during the read-only preflight.
    _read_only_mariadb_factory(host, port, database, user, password)
    tables = _source_tables(host, port, database, user, password)
    moment = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    basename = f"penx-mariadb-{moment}-{uuid.uuid4().hex}"
    final_sql = target / f"{basename}.sql"
    final_json = target / f"{basename}.json"
    staging_sql = None
    staging_json = None
    try:
        with tempfile.NamedTemporaryFile(
                mode="wb", prefix=".penx-mariadb-", suffix=".sql.tmp",
                dir=target, delete=False) as stream:
            staging_sql = Path(stream.name)
            os.chmod(staging_sql, 0o600)
            child_env = os.environ.copy()
            child_env.pop("PENX_MARIADB_BACKUP_PASSWORD", None)
            child_env["MYSQL_PWD"] = password
            arguments = [
                executable, "--no-defaults", "--protocol=TCP",
                f"--host={host}", f"--port={port}", f"--user={user}",
                "--single-transaction", "--quick", "--skip-lock-tables",
                "--skip-add-locks", "--skip-disable-keys",
                "--skip-add-drop-table", "--skip-triggers",
                "--skip-routines", "--skip-events",
                "--default-character-set=utf8mb4", database,
            ]
            # Stderr may disclose DB identifiers; do not persist/echo it.
            result = subprocess.run(
                arguments, stdout=stream, stderr=subprocess.DEVNULL,
                env=child_env, timeout=180, check=False,
            )
        if result.returncode != 0:
            raise ValueError("MariaDB dump client failed")
        length = staging_sql.stat().st_size
        if not 0 < length <= MAX_DUMP_BYTES:
            raise ValueError("MariaDB dump is empty or exceeds size limit")
        checksum = hashlib.sha256()
        with staging_sql.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                checksum.update(chunk)
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        manifest = {
            "schema": SCHEMA,
            "status": "complete-hash-verified",
            "file": final_sql.name,
            "source_database": database,
            "tables": tables,
            "created_at": stamp,
            "size_bytes": length,
            "sha256": checksum.hexdigest(),
            "capture_method": "mariadb-dump-single-transaction-innodb",
        }
        with tempfile.NamedTemporaryFile(
                mode="wb", prefix=".penx-mariadb-", suffix=".json.tmp",
                dir=target, delete=False) as handle:
            staging_json = Path(handle.name)
            os.chmod(staging_json, 0o600)
            handle.write((json.dumps(manifest, sort_keys=True) + "\n").encode("utf-8"))
        # Exclusive publication avoids overwriting an existing verified pair.
        os.link(staging_sql, final_sql)
        os.link(staging_json, final_json)
        return verify_logical_backup(final_sql)
    finally:
        if staging_sql is not None:
            staging_sql.unlink(missing_ok=True)
        if staging_json is not None:
            staging_json.unlink(missing_ok=True)
        # Orphan SQL files cannot verify; remove if manifest wasn't published.
        if not final_json.exists():
            final_sql.unlink(missing_ok=True)

