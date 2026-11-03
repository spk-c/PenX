"""Verified SQLite backup/restore with a metadata-only manifest (PX-004).

A backup is a file pair: ``<name>.sqlite`` and ``<name>.json``. The manifest
is metadata only (schema version, size, SHA-256, creation time) and is
written only after the database file has been fully written and hashed.

A backup is valid only when all of these hold: the manifest parses and says
``status: verified`` for exactly this file, the file exists, its size and
SHA-256 match the manifest, ``PRAGMA integrity_check`` passes, and its schema
version is not newer than the one this PenX understands. A crash or interrupt
leaves at most a ``.tmp`` file or a manifest without its database file;
neither state passes verification.

Restore never overwrites in place: the live database is itself backed up
first (unless it does not exist), the replacement is staged as a temp file in
the same directory and moved into place with ``os.replace``. If migration of
the staged copy fails, the live database is left byte-identical.
"""
from __future__ import annotations

from contextlib import closing
import hashlib
import json
import os
import shutil
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Any

from penx_app.storage.schema_migrations import SCHEMA_VERSION, initialize_sqlite
from penx_app.storage.session_repository import table_row_counts
from penx_app.storage.sqlite_use_lock import SQLiteDatabaseInUse, SQLiteUseLock

BACKUP_SCHEMA = "penx-backup-v1"
_CHUNK_SIZE = 1024 * 1024


class BackupError(Exception):
    """Raised when a backup cannot be created, verified, previewed or restored."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(_CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _unique_backup_name(dest_dir: Path) -> str:
    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    return f"penx-backup-{stamp}-{uuid.uuid4().hex[:8]}.sqlite"


def _resolve_backup(path: Path) -> tuple[Path, Path]:
    """Map a database file, manifest file or directory onto the (db, manifest) pair."""
    path = Path(path)
    if path.is_dir():
        candidates = sorted(path.glob("penx-backup-*.sqlite"))
        if not candidates:
            candidates = sorted(path.glob("*.sqlite"))
        if not candidates:
            raise BackupError(f"No backup found in {path}")
        return candidates[-1], candidates[-1].with_suffix(".json")
    if path.suffix == ".sqlite":
        return path, path.with_suffix(".json")
    if path.suffix == ".json":
        db = path.with_suffix(".sqlite")
        return db, path
    raise BackupError(f"Expected a .sqlite or .json backup file: {path}")


def create_backup(source: Path, dest_dir: Path) -> tuple[Path, dict[str, Any]]:
    """Create a verified backup of ``source`` inside ``dest_dir``.

    Uses SQLite's online backup API, which captures committed WAL pages
    while the source may still be open. The source is opened read-only and
    is never modified.
    """
    source = Path(source)
    dest_dir = Path(dest_dir)
    if not source.is_file():
        raise BackupError(f"Source database not found: {source}")
    dest_dir.mkdir(parents=True, exist_ok=True)

    final_db = dest_dir / _unique_backup_name(dest_dir)
    final_manifest = final_db.with_suffix(".json")
    tmp_db = final_db.with_name(final_db.name + ".tmp")
    tmp_manifest = final_manifest.with_name(final_manifest.name + ".tmp")
    try:
        with closing(
            sqlite3.connect(source.as_uri() + "?mode=ro", uri=True)
        ) as src, closing(sqlite3.connect(str(tmp_db))) as dst:
            src.backup(dst)
            version = dst.execute("PRAGMA user_version").fetchone()[0]
        size = tmp_db.stat().st_size
        digest = _sha256(tmp_db)
        manifest = {
            "schema": BACKUP_SCHEMA,
            "status": "verified",
            "file": final_db.name,
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "source_schema_version": version,
            "size_bytes": size,
            "sha256": digest,
        }
        manifest_bytes = (
            json.dumps(manifest, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")
        tmp_manifest.write_bytes(manifest_bytes)
        os.replace(tmp_manifest, final_manifest)
        os.replace(tmp_db, final_db)
    except BaseException as exc:
        for orphan in (tmp_db, tmp_manifest, final_manifest):
            orphan.unlink(missing_ok=True)
        raise BackupError(f"Backup creation failed: {exc}") from exc
    return final_db, manifest


def verify_backup(path: Path) -> dict[str, Any]:
    """Verify a backup pair; never raises for an invalid backup.

    Returns a report with ``valid`` and the collected ``reasons``. Only I/O
    or resolution failures raise ``BackupError``.
    """
    db_path, manifest_path = _resolve_backup(path)
    report: dict[str, Any] = {
        "db": str(db_path),
        "manifest": str(manifest_path),
        "valid": False,
        "reasons": [],
        "size_bytes": None,
        "sha256": None,
        "schema_version": None,
    }
    reasons: list[str] = []
    if not manifest_path.is_file():
        reasons.append(f"manifest missing: {manifest_path.name}")
        report.update(reasons=reasons)
        return report
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        report.update(reasons=["manifest unreadable"])
        return report
    if not isinstance(manifest, dict) or manifest.get("schema") != BACKUP_SCHEMA:
        report.update(reasons=["manifest has unexpected schema"])
        return report
    if manifest.get("status") != "verified":
        reasons.append("manifest status is not verified")
    if manifest.get("file") != db_path.name:
        reasons.append("manifest names a different file")
    expected_size = manifest.get("size_bytes")
    expected_digest = manifest.get("sha256")
    if not db_path.is_file():
        reasons.append(f"database file missing: {db_path.name}")
    else:
        actual_size = db_path.stat().st_size
        report["size_bytes"] = actual_size
        if isinstance(expected_size, int) and actual_size != expected_size:
            reasons.append(
                f"size mismatch (manifest {expected_size}, actual {actual_size})"
            )
        actual_digest = _sha256(db_path)
        report["sha256"] = actual_digest
        if not isinstance(expected_digest, str) or actual_digest != expected_digest:
            reasons.append("sha256 mismatch")
        try:
            with closing(
                sqlite3.connect(db_path.as_uri() + "?mode=ro", uri=True)
            ) as conn:
                # Diagnostics may quote raw bytes from a corrupt page; the
                # only value we compare strictly is the first column.
                conn.text_factory = lambda b: b.decode("utf-8", "replace")
                integrity = conn.execute("PRAGMA integrity_check").fetchone()
                version = conn.execute("PRAGMA user_version").fetchone()[0]
        except (sqlite3.Error, OSError, UnicodeDecodeError) as exc:
            # Corrupt pages make the integrity rows undecodable; that is
            # itself the corruption signal.
            reasons.append(f"database unreadable: {exc}")
        else:
            report["schema_version"] = version
            if integrity is None or integrity[0] != "ok":
                reasons.append("integrity_check failed")
            if not isinstance(version, int) or version < 0:
                reasons.append(f"schema version invalid: {version!r}")
            elif version > SCHEMA_VERSION:
                reasons.append(
                    f"schema version {version} is newer than {SCHEMA_VERSION}"
                )
    report.update(valid=not reasons, reasons=reasons)
    return report


def preview_restore(path: Path) -> dict[str, Any]:
    """Inspect a backup and dry-run the migration without touching it.

    The migration dry run happens on a throwaway copy in the same directory,
    so the backup file's bytes (and hash) are guaranteed unchanged.
    """
    report = verify_backup(path)
    if not report["valid"]:
        raise BackupError("Backup not valid: " + "; ".join(report["reasons"]))
    db_path = Path(report["db"])
    with closing(sqlite3.connect(db_path.as_uri() + "?mode=ro", uri=True)) as ro:
        version = ro.execute("PRAGMA user_version").fetchone()[0]
        rows = table_row_counts(ro)
    migration: dict[str, Any] = {
        "required": version < SCHEMA_VERSION,
        "succeeds": None,
        "target_schema_version": None,
        "error": None,
    }
    if version < SCHEMA_VERSION:
        tmp = db_path.with_name(f".preview-{uuid.uuid4().hex[:8]}.tmp")
        try:
            shutil.copyfile(db_path, tmp)
            with closing(sqlite3.connect(str(tmp))) as conn:
                initialize_sqlite(conn)
                target = conn.execute("PRAGMA user_version").fetchone()[0]
            migration["succeeds"] = True
            migration["target_schema_version"] = target
        except (sqlite3.Error, ValueError, OSError) as exc:
            migration["succeeds"] = False
            migration["error"] = str(exc)
        finally:
            tmp.unlink(missing_ok=True)
            for suffix in ("-wal", "-shm"):
                Path(str(tmp) + suffix).unlink(missing_ok=True)
    else:
        migration["succeeds"] = True
        migration["target_schema_version"] = version
    return {
        "db": report["db"],
        "manifest": report["manifest"],
        "size_bytes": report["size_bytes"],
        "sha256": report["sha256"],
        "schema_version": version,
        "row_counts": rows,
        "migration": migration,
    }


def restore(backup: Path, live_db: Path, backup_dir: Path) -> dict[str, Any]:
    """Fail closed while managed PenX connections still use the live database."""
    try:
        with SQLiteUseLock(live_db, exclusive=True, timeout=0.1):
            return _restore_unlocked(backup, live_db, backup_dir)
    except SQLiteDatabaseInUse as exc:
        raise BackupError(str(exc)) from exc


def _restore_unlocked(backup: Path, live_db: Path, backup_dir: Path) -> dict[str, Any]:
    """Restore a verified backup over ``live_db`` (atomic, never in place).

    If ``live_db`` exists it is backed up into ``backup_dir`` first; the
    replacement is staged as a temp file, migrated and integrity-checked
    before ``os.replace``. On any failure the live database is left
    byte-identical (or absent, if it was absent before).
    """
    report = verify_backup(backup)
    if not report["valid"]:
        raise BackupError("Backup not valid: " + "; ".join(report["reasons"]))
    db_path = Path(report["db"])
    live_db = Path(live_db)
    backup_dir = Path(backup_dir)
    if live_db.exists() and not live_db.is_file():
        raise BackupError(f"Live database path is not a file: {live_db}")

    pre_restore: str | None = None
    if live_db.exists():
        pre_restore_db, _ = create_backup(live_db, backup_dir)
        pre_restore = str(pre_restore_db)

    original_journal: str | None = None
    if live_db.exists():
        with closing(
            sqlite3.connect(live_db.as_uri() + "?mode=ro", uri=True)
        ) as conn:
            original_journal = conn.execute("PRAGMA journal_mode").fetchone()[0]

    tmp = live_db.with_name(live_db.name + ".restoring.tmp")
    try:
        shutil.copyfile(db_path, tmp)
        with closing(sqlite3.connect(str(tmp))) as conn:
            initialize_sqlite(conn)
            integrity = conn.execute("PRAGMA integrity_check").fetchone()
            if integrity is None or integrity[0] != "ok":
                raise BackupError("Staged restore failed integrity_check")
            target_version = conn.execute("PRAGMA user_version").fetchone()[0]
            if original_journal == "wal":
                conn.execute("PRAGMA journal_mode=WAL")
        for suffix in ("-wal", "-shm"):
            Path(str(tmp) + suffix).unlink(missing_ok=True)
        os.replace(tmp, live_db)
        for suffix in ("-wal", "-shm"):
            Path(str(live_db) + suffix).unlink(missing_ok=True)
    except BaseException as exc:
        for suffix in ("", "-wal", "-shm"):
            Path(str(tmp) + suffix).unlink(missing_ok=True)
        if not isinstance(exc, BackupError):
            raise BackupError(f"Restore failed: {exc}") from exc
        raise
    return {
        "restored": str(live_db),
        "pre_restore_backup": pre_restore,
        "schema_version": target_version,
    }
