"""Offline-only verification of saved versioned metadata and raw captures."""
from __future__ import annotations

import argparse
import hashlib
import json
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


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="penx evidence verify")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--metadata",
                        help="Raw ScanResult.metadata() JSON file, not a report")
    source.add_argument("--session", type=int,
                        help="Positive ID of a saved interactive assessment")
    parser.add_argument("--sqlite-db",
                        help="Existing SQLite database, opened read-only; --session only")
    parser.add_argument("--artifacts", required=True,
                        help="Directory with opted-in SHA-256 raw captures")
    parser.add_argument("--report",
                        help="Also verify the matching penx-scan-v1 JSON report binding; --metadata only")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code) if isinstance(exc.code, int) else 2
    try:
        if args.session is not None:
            if args.sqlite_db is None or args.report is not None:
                raise ValueError("Session verification requires --sqlite-db, not --report")
            summary = verify_session_provenance(
                args.session, args.artifacts,
                _read_only_sqlite_factory(args.sqlite_db))
        else:
            if args.sqlite_db is not None:
                raise ValueError("--sqlite-db is valid only with --session")
            summary = verify_metadata_file(args.metadata, args.artifacts,
                                           report_file=args.report)
    except (OSError, ValueError, UnicodeError, TypeError,
            KeyError, sqlite3.Error):
        # Never echo arbitrary file content, target, errors containing paths
        # or secret-bearing output excerpts to stdout.
        print(json.dumps({"status": "unverified", "error": "provenance-check-failed"}))
        return 2
    print(json.dumps(summary, ensure_ascii=True))
    return 0
