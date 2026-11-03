"""Offline-only verification of saved versioned metadata and raw captures."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sqlite3
from dataclasses import asdict
from pathlib import Path

from penx_app.domain.scan_models import ScanResult
from penx_app.storage.raw_artifacts import revalidate_retained_evidence

MAX_METADATA_INPUT_BYTES = 100_000
MAX_REPORT_INPUT_BYTES = 32 * 1024 * 1024


def _check_report_binding(report_file: str | Path,
                          metadata_path: Path, raw_metadata: bytes,
                          stored: ScanResult) -> None:
    """Validate report->metadata and ordered per-adapter references offline.

    This verifies an internally consistent provenance manifest, not
    authorship or the user's actual authorization/scan target identity.
    """
    report_path = Path(report_file)
    if report_path.is_symlink() or not report_path.is_file():
        raise ValueError("Report must be a regular nonlinked file")
    with report_path.open("rb") as handle:
        raw_report = handle.read(MAX_REPORT_INPUT_BYTES + 1)
    if len(raw_report) > MAX_REPORT_INPUT_BYTES:
        raise ValueError("Report exceeds bounded input size")

    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate report JSON property")
            result[key] = value
        return result

    def invalid_constant(_value):
        raise ValueError("Non-finite report number")

    report = json.loads(raw_report.decode("utf-8"), object_pairs_hook=unique_object,
                        parse_constant=invalid_constant)
    if (not isinstance(report, dict) or report.get("schema") != "penx-scan-v1"
            or report.get("session") is not None):
        raise ValueError("Unexpected headless report schema or session")
    if (stored.plan_summary is None
            or report.get("profile") != asdict(stored.plan_summary)
            or report.get("scanner_configuration") != [
                item.to_dict() for item in stored.scanner_configuration]
            or report.get("dependencies") != [
                list(edge) for edge in stored.dependencies]):
        raise ValueError("Report/metadata scan plan mismatch")
    manifest = report.get("provenance_manifest")
    if (not isinstance(manifest, dict) or set(manifest) != {
            "metadata_file", "metadata_sha256", "status"}
            or manifest["metadata_file"] != metadata_path.name
            or manifest["status"] != "stored-reference-not-revalidated"
            or manifest["metadata_sha256"] != hashlib.sha256(
                raw_metadata.rstrip(b"\r\n")).hexdigest()):
        raise ValueError("Report/metadata manifest mismatch")
    adapters = report.get("adapters")
    if not isinstance(adapters, list) or len(adapters) != len(stored.results):
        raise ValueError("Report/metadata adapter count mismatch")
    for report_row, saved_row in zip(adapters, stored.results, strict=True):
        if (not isinstance(report_row, dict)
                or report_row.get("id") != saved_row.scanner_id
                or report_row.get("status") != saved_row.status
                or report_row.get("reason") != saved_row.reason
                or type(report_row.get("evidence")) is not bool
                or report_row.get("evidence") != saved_row.evidence
                or report_row.get("raw_artifact") != (
                    asdict(saved_row.raw_artifact)
                    if saved_row.raw_artifact is not None else None)
                or report_row.get("stdout_capture") != (
                    asdict(saved_row.stdout_capture)
                    if saved_row.stdout_capture is not None else None)):
            raise ValueError("Report adapter provenance mismatch")


def verify_metadata_file(metadata_file: str | Path,
                         artifacts_directory: str | Path,
                         report_file: str | Path | None = None) -> dict:
    """Read one raw ScanResult.metadata() JSON file, never a scan target.

    A scan's headless report JSON is not itself a metadata document. Use
    the saved scan_metadata field (or output of ScanResult.metadata()).
    """
    path = Path(metadata_file)
    if path.is_symlink() or not path.is_file():
        raise ValueError("Metadata must be a regular file")
    with path.open("rb") as handle:
        raw = handle.read(MAX_METADATA_INPUT_BYTES + 1)
    if len(raw) > MAX_METADATA_INPUT_BYTES:
        raise ValueError("Metadata input exceeds size limit")
    stored = ScanResult.from_metadata(raw.decode("utf-8"))
    if report_file is not None:
        _check_report_binding(report_file, path, raw, stored)
    verified_anchors = revalidate_retained_evidence(stored, artifacts_directory)
    verified_sources = sum(row.evidence for row in stored.results)
    return {
        "status": "verified-retained-integrity",
        "raw_sources_verified": verified_sources,
        "report_binding_verified": report_file is not None,
        "stdout_byte_sources_verified": sum(
            row.stdout_capture is not None for row in stored.results),
        "anchors_verified": len(verified_anchors),
        "meaning": "Whole opted-in captured text and quoted offsets match saved hashes; scanner authenticity and vulnerability applicability not established.",
    }


def verify_session_provenance(
    session_id: int, artifacts_directory: str | Path, connection_factory,
) -> dict:
    """Audit a stored assessment without executing scanners or a model.

    Deliberately strict first field slice: every adapter must have saved,
    integrity-verifiable source text, at least one eligible exact subprocess
    stdout proof must be present, and the complete original recon report
    must exactly re-render from those sources. An incomplete/legacy session
    does not receive a partial or misleading "verified" certificate.
    """
    from penx_app.scanners.scan_results import format_recon_for_llm
    from penx_app.storage.raw_artifacts import (
        validate_artifact, revalidate_retained_evidence,
    )
    from penx_app.storage.session_repository import SessionRepository

    if type(session_id) is not int or session_id < 1:
        raise ValueError("Invalid session ID")
    snapshot = SessionRepository(connection_factory).snapshot(session_id)
    if (snapshot.history is None or snapshot.history.session_id != session_id
            or snapshot.history.status != "active"
            or snapshot.summary is None or snapshot.scan_result is None):
        raise ValueError("No active saved assessment with scanner metadata")
    stored = snapshot.scan_result
    if (not stored.results
            or not any(row.stdout_capture is not None for row in stored.results)
            or any(not row.evidence or row.status != "COMPLETE"
                   or row.raw_artifact is None for row in stored.results)):
        raise ValueError("Session is not fully eligible for byte attestation")

    verified_anchors = revalidate_retained_evidence(stored, artifacts_directory)
    recovered = tuple(validate_artifact(row, artifacts_directory)
                      for row in stored.results)
    reconstructed = str(format_recon_for_llm(ScanResult(recovered)))
    if reconstructed != snapshot.summary.raw_scan:
        raise ValueError("Persisted session raw text does not match scanner sources")
    return {
        "status": "verified-retained-integrity",
        "session_id": session_id,
        "session_raw_text_verified": True,
        "raw_sources_verified": len(recovered),
        "stdout_byte_sources_verified": sum(
            row.stdout_capture is not None for row in recovered),
        "anchors_verified": len(verified_anchors),
        "meaning": "Stored session recon text, complete retained adapter sources and opted-in original stdout bytes match; scanner identity, target authorization and exploitability are not attested.",
    }


def _read_only_sqlite_factory(path: str | Path):
    """Explicit existing SQLite file; never create or migrate a DB."""
    from penx_app.storage.db_backend import SQLiteConnection

    candidate = Path(path).expanduser()
    if candidate.is_symlink() or not candidate.is_file():
        raise ValueError("SQLite verification requires an existing regular file")
    resolved = candidate.resolve(strict=True)

    def connect():
        conn = sqlite3.connect(resolved.as_uri() + "?mode=ro",
                               uri=True, timeout=5)
        try:
            conn.execute("PRAGMA query_only=ON")
        except BaseException:
            conn.close()
            raise
        return SQLiteConnection(conn)

    return connect



def _read_only_mariadb_factory(
    host: str, port: int, database: str, user: str, password: str,
):
    """Connect only to explicit local MariaDB; no migrations or implicit writes.

    A loopback restriction means operators can use a local SSH tunnel for
    remote servers, without transmitting passwords to a remote port in
    plaintext by accident. Password is supplied by dedicated env var,
    never CLI args or project .env defaults.
    """
    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("Read-only MariaDB verification requires loopback")
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("Invalid MariaDB port")
    if not isinstance(database, str) or not re.fullmatch(
            r"[A-Za-z0-9_]{1,64}", database):
        raise ValueError("Invalid MariaDB database name")
    if not isinstance(user, str) or not re.fullmatch(
            r"[A-Za-z0-9_.@-]{1,128}", user):
        raise ValueError("Invalid MariaDB read-only user")
    if not isinstance(password, str) or not password:
        raise ValueError("Missing dedicated MariaDB verification password")

    # Deliberately lazy: mariadb integration is an optional dependency.
    import mysql.connector

    def connect():
        conn = mysql.connector.connect(
            host=host, port=port, database=database, user=user,
            password=password, connection_timeout=5, autocommit=False,
            allow_local_infile=False,
        )
        try:
            # Enforce both repeatable snapshot semantics and transaction
            # access mode on the server. Do not query with the connection
            # unless the server accepted the READ ONLY transaction.
            conn.start_transaction(
                consistent_snapshot=True, isolation_level="REPEATABLE READ",
                readonly=True,
            )
        except BaseException:
            conn.close()
            raise
        return conn

    return connect


def _verify_mariadb_session(
    session_id: int, artifacts_directory: str | Path,
    host: str, port: int, database: str, user: str, password: str,
) -> dict:
    """Normalize connector exceptions before the secret-free CLI boundary."""
    factory = _read_only_mariadb_factory(
        host, port, database, user, password)
    import mysql.connector
    try:
        result = verify_session_provenance(
            session_id, artifacts_directory, factory)
    except mysql.connector.Error as exc:
        # Do not print connector errors, which may include connection strings,
        # hosts or usernames. Preserve causal traceback for developer logs.
        raise ValueError("MariaDB read-only verification failed") from exc
    result["backend"] = "mariadb-read-only"
    return result


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="penx evidence verify")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--metadata",
                        help="Raw ScanResult.metadata() JSON file, not a report")
    source.add_argument("--session", type=int,
                        help="Positive ID of a saved interactive assessment")
    parser.add_argument("--sqlite-db",
                        help="Existing SQLite database, opened read-only; --session only")
    parser.add_argument("--mariadb-host",
                        help="Explicit loopback MariaDB endpoint or local SSH tunnel; --session only")
    parser.add_argument("--mariadb-port", type=int, default=None,
                        help="MariaDB verification port; default 3306")
    parser.add_argument("--mariadb-db",
                        help="Existing database name; no migrations")
    parser.add_argument("--mariadb-user",
                        help="Dedicated SELECT-only database user")
    parser.add_argument("--artifacts", required=True,
                        help="Directory with opted-in SHA-256 raw captures")
    parser.add_argument("--report",
                        help="Also verify the matching penx-scan-v1 JSON report binding; --metadata only")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code) if isinstance(exc.code, int) else 2
    try:
        maria_options = (
            args.mariadb_host, args.mariadb_db, args.mariadb_user,
            args.mariadb_port)
        maria_selected = any(part is not None for part in maria_options)
        if args.session is not None:
            if args.report is not None or (args.sqlite_db is not None
                                           and maria_selected):
                raise ValueError("Select one supported session backend")
            if maria_selected:
                if not all((args.mariadb_host, args.mariadb_db,
                            args.mariadb_user)):
                    raise ValueError("Incomplete MariaDB connection options")
                summary = _verify_mariadb_session(
                    args.session, args.artifacts,
                    args.mariadb_host, args.mariadb_port
                    if args.mariadb_port is not None else 3306,
                    args.mariadb_db, args.mariadb_user,
                    os.environ.get("PENX_VERIFY_MARIADB_PASSWORD", ""))
            else:
                if args.sqlite_db is None:
                    raise ValueError("Session verification requires an explicit DB")
                summary = verify_session_provenance(
                    args.session, args.artifacts,
                    _read_only_sqlite_factory(args.sqlite_db))
        else:
            if args.sqlite_db is not None or maria_selected:
                raise ValueError("Database options are for --session only")
            summary = verify_metadata_file(args.metadata, args.artifacts,
                                           report_file=args.report)
    except (OSError, ValueError, UnicodeError, TypeError, ImportError,
            KeyError, sqlite3.Error):
        # Never echo arbitrary file content, target, errors containing paths
        # or secret-bearing output excerpts to stdout.
        print(json.dumps({"status": "unverified", "error": "provenance-check-failed"}))
        return 2
    print(json.dumps(summary, ensure_ascii=True))
    return 0
