#!/usr/bin/env python3
"""Verify dependency versions loaded by a built PenX executable, not pip.

No scanner, internet access or production data is used. The frozen executable
itself reports imported dnspython, certifi and Pillow versions as JSON.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Callable

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = ("certifi", "dnspython", "pillow")
PACKAGE_LINE = re.compile(r"^([A-Za-z0-9_.-]+)==([^\\\s]+)")


def locked_versions(lockfile: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in lockfile.read_text(encoding="utf-8").splitlines():
        match = PACKAGE_LINE.match(line)
        if match is None:
            continue
        name = match.group(1).lower().replace("_", "-")
        if name in values:
            raise ValueError(f"Duplicate locked requirement: {name}")
        values[name] = match.group(2)
    missing = set(REQUIRED) - values.keys()
    if missing:
        raise ValueError("Missing locked requirement(s): " + ", ".join(sorted(missing)))
    return {name: values[name] for name in REQUIRED}


def verify_executable(executable: Path, expected: dict[str, str],
                      *, run: Callable = subprocess.run) -> None:
    result = run([str(executable), "--release-dependencies"],
                 text=True, capture_output=True, check=False, timeout=30)
    if result.returncode != 0:
        raise ValueError(f"Frozen dependency report failed (exit {result.returncode})")
    try:
        report = json.loads(result.stdout)
    except (ValueError, TypeError) as exc:
        raise ValueError("Frozen dependency report is not valid JSON") from exc
    if not isinstance(report, dict) or report.get("frozen") is not True:
        raise ValueError("Dependency report did not come from a frozen executable")
    packages = report.get("packages")
    if not isinstance(packages, dict) or set(packages) != set(REQUIRED):
        raise ValueError("Frozen dependency report has missing or unexpected packages")
    for package in REQUIRED:
        actual = packages[package]
        if not isinstance(actual, str) or actual != expected[package]:
            raise ValueError(
                f"Frozen {package} version mismatch: expected {expected[package]!r}, found {actual!r}"
            )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executable", type=Path, required=True)
    parser.add_argument("--lockfile", type=Path, default=ROOT / "requirements.lock.txt")
    args = parser.parse_args(argv)
    try:
        if not args.executable.is_file():
            raise ValueError("Built executable does not exist")
        expected = locked_versions(args.lockfile)
        verify_executable(args.executable, expected)
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        print(f"[FAIL] Frozen dependency verification: {exc}", file=sys.stderr)
        return 1
    for name in REQUIRED:
        print(f"[OK] Frozen {name} == {expected[name]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
