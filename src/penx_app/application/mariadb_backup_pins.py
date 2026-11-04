"""PX-004 offline external checksum pins for a saved MariaDB backup pair.

Neither a manifest SHA-256 nor a SQL SHA-256 is trustworthy merely because
both are adjacent on the same disk. Compare against TWO independent operator-
recorded hashes. This authenticates only matching bytes to the supplied pins,
not who supplied the pins or whether the SQL is valid/complete/restorable.
"""
from __future__ import annotations

import hashlib
import hmac
from pathlib import Path

from penx_app.application.mariadb_backup import (
    MAX_MANIFEST_BYTES, _SHA, verify_logical_backup,
)

PIN_REPORT_SCHEMA = "penx-mariadb-operator-pins-v1"


def _manifest_bytes(path: Path) -> bytes:
    """Bounded manifest bytes, independently of the SQL SHA-256 check."""
    if path.is_symlink() or not path.is_file():
        raise ValueError("Pinned manifest must be an existing regular file")
    with path.open("rb") as source:
        data = source.read(MAX_MANIFEST_BYTES + 1)
    if not data or len(data) > MAX_MANIFEST_BYTES:
        raise ValueError("Pinned manifest size is invalid")
    return data


def verify_pinned_logical_backup(
    file: str | Path, *, expected_sql_sha256: str,
    expected_manifest_sha256: str,
) -> dict:
    """Match saved bytes against two *externally recorded* SHA-256 values.

    Does not import SQL or contact MariaDB. A caller-provided digest proves
    neither the digest's origin nor the source data's authenticity.
    """
    # Type/format gate before reading any file or outputting untrusted input.
    if (not isinstance(expected_sql_sha256, str)
            or _SHA.fullmatch(expected_sql_sha256) is None
            or not isinstance(expected_manifest_sha256, str)
            or _SHA.fullmatch(expected_manifest_sha256) is None):
        raise ValueError("Expected two lowercase 64-character SHA-256 pins")
    item = Path(file)
    if item.suffix not in {".sql", ".json"}:
        raise ValueError("Expected an explicit MariaDB .sql or .json backup")
    manifest_file = item.with_suffix(".json")

    # Before-and-after manifest hash checks detect ordinary changes during
    # verification. This is NOT an atomic lock against adversarial file swaps.
    first_manifest = hashlib.sha256(_manifest_bytes(manifest_file)).hexdigest()
    if not hmac.compare_digest(first_manifest, expected_manifest_sha256):
        raise ValueError("Operator manifest pin differs from saved manifest")

    report = verify_logical_backup(item)
    if not hmac.compare_digest(report["sha256"], expected_sql_sha256):
        raise ValueError("Operator SQL pin differs from saved dump")

    second_manifest = hashlib.sha256(_manifest_bytes(manifest_file)).hexdigest()
    if not hmac.compare_digest(second_manifest, expected_manifest_sha256):
        raise ValueError("Operator manifest changed during backup verification")

    return {
        "schema": PIN_REPORT_SCHEMA,
        "status": "operator-pinned-file-identity-only",
        "sql_sha256": report["sha256"],
        "manifest_sha256": second_manifest,
        "sql_size_bytes": report["size_bytes"],
        "tables_in_manifest": report["tables_in_manifest"],
        "supplied_sql_pin_matches": True,
        "supplied_manifest_pin_matches": True,
        "pin_origin_authenticated": False,
        "historical_backup_rows_verified": False,
        "sql_semantics_verified": False,
        "restore_available": False,
        "sql_executed": False,
        "database_modified": False,
        "note": (
            "Both saved file hashes match the two supplied external pins. "
            "No proof of pin origin, historical SQL content, database snapshot, "
            "SQL safety or authorization to restore."
        ),
    }
