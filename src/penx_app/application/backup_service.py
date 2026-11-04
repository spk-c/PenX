"""Headless verified backup/restore commands (PX-004).

Exit codes:
    0  success, or verify/preview with a valid backup that would restore
    1  verify/preview: backup not valid, or migration dry run failed
    2  usage, storage or restore error (nothing was replaced)
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
from typing import Any

from penx_app.app_paths import default_backup_dir
from penx_app.storage import backup as backup_store

import penx_app.config as config


def _live_db(explicit: str | None) -> Path | None:
    """Resolve the live database; None means the engine is not a SQLite file."""
    if explicit is not None:
        return Path(explicit).expanduser()
    if config.DB_ENGINE == "mariadb":
        return None
    return Path(config.DB_PATH).expanduser()


def _print_backup(report: dict[str, Any]) -> None:
    print(f"Backup: {report['db']}")
    print(f"Manifest: {report['manifest']}")
    if report["size_bytes"] is not None:
        print(f"Size: {report['size_bytes']} bytes")
    if report["sha256"] is not None:
        print(f"SHA-256: {report['sha256']}")
    if report["schema_version"] is not None:
        print(f"Schema version: {report['schema_version']}")


def _cmd_create(args: argparse.Namespace) -> int:
    source = _live_db(args.db)
    if source is None:
        print("Database engine is 'mariadb'; pass --db <path> to back up a "
              "SQLite file.", file=sys.stderr)
        return 2
    dest = Path(args.output_dir).expanduser() if args.output_dir else default_backup_dir()
    try:
        db_path, manifest = backup_store.create_backup(source, dest)
    except backup_store.BackupError as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 2
    report = backup_store.verify_backup(db_path)
    _print_backup(report)
    if not report["valid"]:
        print(f"[FAIL] Backup not valid: {'; '.join(report['reasons'])}",
              file=sys.stderr)
        return 2
    print("[OK] Backup created and verified.")
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    try:
        report = backup_store.verify_backup(Path(args.file))
    except backup_store.BackupError as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 2
    _print_backup(report)
    if report["valid"]:
        print("[OK] Backup verified.")
        return 0
    print(f"[FAIL] Backup not valid: {'; '.join(report['reasons'])}")
    return 1


def _cmd_preview(args: argparse.Namespace) -> int:
    try:
        preview = backup_store.preview_restore(Path(args.file))
    except backup_store.BackupError as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 1
    print(f"Backup: {preview['db']}")
    print(f"Schema version: {preview['schema_version']}")
    print("Rows:")
    for table in sorted(preview["row_counts"]):
        print(f"  {table}: {preview['row_counts'][table]}")
    migration = preview["migration"]
    if not migration["required"]:
        print("Migration: not required")
        return 0
    if migration["succeeds"]:
        print(f"Migration: required; dry run OK "
              f"(target schema version {migration['target_schema_version']})")
        return 0
    print(f"Migration: required; dry run FAILED: {migration['error']}")
    return 1


def _cmd_restore(args: argparse.Namespace) -> int:
    target = _live_db(args.db)
    if target is None:
        print("Database engine is 'mariadb'; pass --db <path> to restore a "
              "SQLite file.", file=sys.stderr)
        return 2
    if not args.confirm:
        print("Restore requires explicit confirmation; pass --confirm "
              "after inspecting the backup with 'penx backup preview'.",
              file=sys.stderr)
        return 2
    dest = Path(args.output_dir).expanduser() if args.output_dir else default_backup_dir()
    try:
        result = backup_store.restore(Path(args.file), target, dest)
    except backup_store.BackupError as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 2
    pre = result["pre_restore_backup"]
    print(f"Pre-restore backup: {pre if pre else 'none (live database did not exist)'}")
    print(f"[OK] Restored {result['restored']} (schema version {result['schema_version']}).")
    return 0



def _mariadb_result(kind: str, args: argparse.Namespace) -> int:
    """Separate, opt-in logical dump commands; never invoke SQLite restore."""
    from penx_app.application import mariadb_backup

    try:
        if kind == "create":
            password = os.environ.get("PENX_MARIADB_BACKUP_PASSWORD", "")
            if not password:
                raise ValueError("Dedicated MariaDB backup credential required")
            result = mariadb_backup.create_logical_backup(
                host=args.host, port=args.port, database=args.database,
                user=args.user, password=password, directory=args.output_dir)
        elif kind == "verify":
            result = mariadb_backup.verify_logical_backup(args.file)
        else:
            result = mariadb_backup.preview_logical_backup(args.file)
    except Exception:
        # SQL server error text, argv, filenames and credentials are
        # intentionally never reflected in CLI output on failure.
        print(json.dumps({"status": "unverified",
                          "error": "mariadb-backup-check-failed"}))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


def _cmd_mariadb_create(args: argparse.Namespace) -> int:
    return _mariadb_result("create", args)


def _cmd_mariadb_verify(args: argparse.Namespace) -> int:
    return _mariadb_result("verify", args)


def _cmd_mariadb_preview(args: argparse.Namespace) -> int:
    return _mariadb_result("preview", args)


def _cmd_mariadb_dump_inspect(args: argparse.Namespace) -> int:
    """Read hash-bound MariaDB SQL for generic red flags; never restore."""
    from penx_app.application.mariadb_dump_diagnostics import inspect_logical_dump

    try:
        report = inspect_logical_dump(args.file)
    except (OSError, UnicodeError, ValueError, TypeError):
        print(json.dumps({"status": "unverified",
                          "error": "mariadb-dump-diagnostic-failed",
                          "restore_available": False}))
        return 2
    print(json.dumps(report, sort_keys=True))
    return 0


def _cmd_mariadb_restore_plan(args: argparse.Namespace) -> int:
    """Non-mutating intent; MariaDB import remains unsupported."""
    from penx_app.application.mariadb_restore_plan import plan_scratch_restore

    try:
        result = plan_scratch_restore(
            args.file, target_schema=args.target_schema)
    except (OSError, ValueError, TypeError, KeyError):
        print(json.dumps({
            "status": "unverified",
            "error": "mariadb-restore-plan-failed",
        }))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0

def _cmd_mariadb_restore_preflight(args: argparse.Namespace) -> int:
    """Read-only server target visibility; never imports backup SQL."""
    from penx_app.application.mariadb_restore_plan import preflight_scratch_target

    try:
        password = os.environ.get("PENX_VERIFY_MARIADB_PASSWORD", "")
        result = preflight_scratch_target(
            args.file, target_schema=args.target_schema,
            host=args.host, port=args.port, database=args.database,
            user=args.user, password=password)
    except Exception:
        # MariaDB client errors can contain credentials or schema details.
        print(json.dumps({"status": "unverified",
                          "error": "mariadb-scratch-preflight-failed"}))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


def _cmd_mariadb_restore_audit(args: argparse.Namespace) -> int:
    """Compare read-only source/scratch metadata without importing SQL."""
    from penx_app.application.mariadb_restore_audit import audit_scratch_restore

    try:
        result = audit_scratch_restore(
            args.file, target_schema=args.target_schema,
            host=args.host, port=args.port,
            source_user=args.source_user,
            source_password=os.environ.get("PENX_VERIFY_MARIADB_PASSWORD", ""),
            target_user=args.target_user,
            target_password=os.environ.get("PENX_SCRATCH_AUDIT_PASSWORD", ""),
            verify_content=args.verify_content,
        )
    except Exception:
        # Never disclose DB driver messages, SQL source text or credentials.
        print(json.dumps({
            "status": "unverified",
            "error": "mariadb-scratch-audit-failed",
        }))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="penx backup",
        description="Verified SQLite backup/restore (PX-004).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_create = sub.add_parser("create", help="Create a verified backup of the live database.")
    p_create.add_argument("--db", default=None, help="SQLite file to back up (default: configured database)")
    p_create.add_argument("--output-dir", default=None, help="Backup directory (default: <data>/backups)")

    p_verify = sub.add_parser("verify", help="Verify a backup pair against its manifest.")
    p_verify.add_argument("--file", required=True, help="Backup .sqlite/.json file or its directory")

    p_preview = sub.add_parser("preview", help="Preview a restore without touching the live database.")
    p_preview.add_argument("--file", required=True, help="Backup .sqlite/.json file or its directory")

    p_restore = sub.add_parser("restore", help="Restore a verified backup over the live database.")
    p_restore.add_argument("--file", required=True, help="Backup .sqlite/.json file or its directory")
    p_restore.add_argument("--db", default=None, help="Live SQLite file (default: configured database)")
    p_restore.add_argument("--output-dir", default=None, help="Directory for the mandatory pre-restore backup")
    p_restore.add_argument("--confirm", action="store_true", help="Explicitly approve the restore")

    # These subcommands are NOT automatic for mariadb-engine users.
    # No in-place MariaDB restore subcommand is exposed.
    p_maria = sub.add_parser(
        "mariadb-create", help="Opt-in local MariaDB dump to a hash-bound file pair")
    p_maria.add_argument("--host", required=True, help="127.0.0.1, localhost, or ::1 only")
    p_maria.add_argument("--port", type=int, default=3306)
    p_maria.add_argument("--database", required=True, help="Existing PenX MariaDB database")
    p_maria.add_argument("--user", required=True, help="Dedicated SELECT-only backup account")
    p_maria.add_argument("--output-dir", required=True,
                         help="Existing private backup directory")
    p_mv = sub.add_parser("mariadb-verify", help="Check SQL dump bytes and manifest offline")
    p_mv.add_argument("--file", required=True, help="Explicit .sql or .json backup")
    p_mp = sub.add_parser("mariadb-preview",
                          help="Offline preview only; never imports SQL")
    p_mp.add_argument("--file", required=True, help="Explicit .sql or .json backup")

    p_inspect = sub.add_parser(
        "mariadb-dump-inspect",
        help="Offline red-flag SQL dump diagnostics; NEVER authorizes restore")
    p_inspect.add_argument("--file", required=True,
                           help="Hash-bound MariaDB .sql or .json backup pair")

    p_plan = sub.add_parser(
        "mariadb-restore-plan",
        help="Offline recovery intent for a NEW scratch schema; no import")
    p_plan.add_argument("--file", required=True, help="Verified MariaDB SQL file")
    p_plan.add_argument(
        "--target-schema", required=True,
        help="Proposed penx_restore_<32-hex> name; existence not checked")

    p_preflight = sub.add_parser(
        "mariadb-restore-preflight",
        help="READ ONLY target schema visibility check; NO restore")
    p_preflight.add_argument("--file", required=True)
    p_preflight.add_argument("--target-schema", required=True)
    p_preflight.add_argument("--host", required=True,
                             help="Loopback MariaDB host only")
    p_preflight.add_argument("--port", type=int, default=3306)
    p_preflight.add_argument("--database", required=True,
                             help="Existing source schema for the read-only login")
    p_preflight.add_argument("--user", required=True,
                             help="Read-only user with explicit SHOW DATABASES privilege")

    p_audit = sub.add_parser(
        "mariadb-restore-audit",
        help="READ ONLY source/scratch schema and row-count comparison")
    p_audit.add_argument("--file", required=True)
    p_audit.add_argument("--target-schema", required=True)
    p_audit.add_argument("--host", required=True, help="Loopback only")
    p_audit.add_argument("--port", type=int, default=3306)
    p_audit.add_argument("--source-user", required=True)
    p_audit.add_argument("--target-user", required=True)
    p_audit.add_argument(
        "--verify-content", action="store_true",
        help="Opt-in bounded row multiset compare; no content logged")

    try:
        args = parser.parse_args(argv)
    except SystemExit:
        return 2
    handlers = {
        "create": _cmd_create,
        "verify": _cmd_verify,
        "preview": _cmd_preview,
        "restore": _cmd_restore,
        "mariadb-create": _cmd_mariadb_create,
        "mariadb-verify": _cmd_mariadb_verify,
        "mariadb-preview": _cmd_mariadb_preview,
        "mariadb-dump-inspect": _cmd_mariadb_dump_inspect,
        "mariadb-restore-plan": _cmd_mariadb_restore_plan,
        "mariadb-restore-preflight": _cmd_mariadb_restore_preflight,
        "mariadb-restore-audit": _cmd_mariadb_restore_audit,
    }
    return handlers[args.command](args)
