"""Explicit local-file PHP2Shell triage CLI; no external requests."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from penx_app.intelligence.php2shell_audit import assess_php2shell
from penx_app.intelligence.php2shell_local_audit import (
    MAX_LOCAL_BYTES, analyze_php2shell_local_artifacts,
)


def _read_file(filename: str | None, label: str) -> str | None:
    if filename is None:
        return None
    try:
        with Path(filename).open("rb") as handle:
            data = handle.read(MAX_LOCAL_BYTES + 1)
    except OSError as exc:
        raise ValueError(f"{label}: cannot read local file ({type(exc).__name__})") from None
    if len(data) > MAX_LOCAL_BYTES:
        raise ValueError(f"{label}: exceeds the 2 MB file limit")
    return data.decode("utf-8-sig", errors="replace")


def audit_cli(args: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Offline-only PHP2Shell log/configuration triage, never an exploit."
    )
    parser.add_argument("--scan-file", help="Previously saved PenX scanner output")
    parser.add_argument("--php-ini", help="Local php.ini; not proof of effective settings")
    parser.add_argument("--access-log", help="Local HTTP access log")
    parser.add_argument("--error-log", help="Local PHP/Apache error log")
    parsed = parser.parse_args(args)
    if not any((parsed.scan_file, parsed.php_ini, parsed.access_log, parsed.error_log)):
        parser.error("supply at least one local evidence file")
    try:
        scan = _read_file(parsed.scan_file, "--scan-file") or ""
        local = analyze_php2shell_local_artifacts(
            php_ini=_read_file(parsed.php_ini, "--php-ini"),
            access_log=_read_file(parsed.access_log, "--access-log"),
            error_log=_read_file(parsed.error_log, "--error-log"),
        )
    except ValueError as exc:
        parser.exit(2, f"PHP2Shell audit: {exc}\n")
    print(json.dumps({
        "schema": "penx-php2shell-offline-audit-v1",
        "release_posture": assess_php2shell(scan),
        "local_triage": local,
    }, indent=2, ensure_ascii=False))
    return 0
