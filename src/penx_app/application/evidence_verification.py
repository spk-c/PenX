"""Offline-only verification of saved versioned metadata and raw captures."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from penx_app.domain.scan_models import ScanResult
from penx_app.storage.raw_artifacts import revalidate_retained_evidence

MAX_METADATA_INPUT_BYTES = 100_000


def verify_metadata_file(metadata_file: str | Path,
                         artifacts_directory: str | Path) -> dict:
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
    verified_anchors = revalidate_retained_evidence(stored, artifacts_directory)
    verified_sources = sum(row.evidence for row in stored.results)
    return {
        "status": "verified-retained-integrity",
        "raw_sources_verified": verified_sources,
        "anchors_verified": len(verified_anchors),
        "meaning": "Whole opted-in captured text and quoted offsets match saved hashes; scanner authenticity and vulnerability applicability not established.",
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="penx evidence verify")
    parser.add_argument("--metadata", required=True,
                        help="Raw ScanResult.metadata() JSON file, not a report")
    parser.add_argument("--artifacts", required=True,
                        help="Directory with opted-in SHA-256 raw captures")
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code) if isinstance(exc.code, int) else 2
    try:
        summary = verify_metadata_file(args.metadata, args.artifacts)
    except (OSError, ValueError, UnicodeError, TypeError, KeyError):
        # Never echo arbitrary file content, target, errors containing paths
        # or secret-bearing output excerpts to stdout.
        print(json.dumps({"status": "unverified", "error": "provenance-check-failed"}))
        return 2
    print(json.dumps(summary, ensure_ascii=True))
    return 0
