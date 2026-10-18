#!/usr/bin/env python3
"""Validate an operator-filled FIELD_ACCEPTANCE.md worksheet.

This is a *structural* and provenance-completeness check, never proof that
hardware tests or human review occurred. No scanner, installer, DB or network
operation is performed.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import re


MATRICES = (
    {
        "heading": "Issue #81 - scanner matrix",
        "keys": tuple("123456789scde"),
        "optional": frozenset({"e"}),
        "columns": 9,
        "status": 2,
    },
    {
        "heading": "Issue #81 - Windows controls",
        "keys": (
            "consent-denial", "navigation-back-esc",
            "ctrl-c-cancel-process-tree", "timeout-process-tree",
            "missing-executable", "missing-permissions",
            "npcap-admin-uac", "npcap-nonadmin",
        ),
        "optional": frozenset(),
        "columns": 6,
        "status": 1,
    },
    {
        "heading": "Issue #82 - recovery and upgrade matrix",
        "keys": (
            "sqlite-wal-consistent-restore",
            "sqlite-migration-duplicates-rollback",
            "mariadb-consistent-restore",
            "mariadb-migration-duplicates-rollback",
            "installer-clean-first-run",
            "installer-v048-upgrade",
            "installer-repair-abort-uninstall",
            "report-long-html-pdf-pagination",
            "report-json-sarif-html-pdf-parity",
            "report-interrupted-publish-recovery",
        ),
        "optional": frozenset(),
        "columns": 7,
        "status": 1,
    },
)
RESULTS = frozenset({"NOT RUN", "PASS", "FAIL", "BLOCKED"})
BLANK = frozenset({"", "-", "NOT RUN", "NOT PROVIDED", "TBD", "TODO", "N/A"})


def _cells(line: str) -> list[str] | None:
    raw = line.strip()
    if not raw.startswith("|") or not raw.endswith("|"):
        return None
    return [x.strip().replace(r"\|", "|")
            for x in re.split(r"(?<!\\)\|", raw[1:-1])]


def validate_worksheet(text: str, *, allow_incomplete: bool = False) -> list[str]:
    """Return actionable violations, rather than silently attesting to a run."""
    errors: list[str] = []
    headings = re.findall(r"(?m)^## (.+?)\s*$", text)
    lines = text.splitlines()
    for matrix in MATRICES:
        heading = matrix["heading"]
        if headings.count(heading) != 1:
            errors.append(f"{heading}: expected exactly one section")
            continue
        marker = "## " + heading
        start = next(i for i, line in enumerate(lines) if line.strip() == marker)
        end = next((i for i in range(start + 1, len(lines))
                    if lines[i].startswith("## ")), len(lines))
        seen: dict[str, list[str]] = {}
        expected = set(matrix["keys"])
        for line in lines[start + 1:end]:
            row = _cells(line)
            if row is None or not row or row[0] in {
                "Choice", "Control", "Scenario",
            } or set(row[0]) <= {"-", " ", ":"}:
                continue
            key = row[0]
            if key not in expected:
                errors.append(f"{heading}: unexpected row {key!r}")
                continue
            if key in seen:
                errors.append(f"{heading}: duplicate row {key!r}")
                continue
            seen[key] = row
            if len(row) != matrix["columns"]:
                errors.append(f"{heading}/{key}: expected {matrix['columns']} columns; got {len(row)}")
                continue
            status = row[matrix["status"]].upper()
            if status not in RESULTS:
                errors.append(f"{heading}/{key}: invalid result {status!r}")
            elif status == "PASS":
                for i, cell in enumerate(row):
                    if i not in (0, matrix["status"]) and cell.upper() in BLANK:
                        errors.append(f"{heading}/{key}: PASS missing column {i + 1} provenance")
            elif not allow_incomplete and key not in matrix["optional"]:
                errors.append(f"{heading}/{key}: {status}, required PASS for sign-off")
        for missing in sorted(expected - seen.keys()):
            errors.append(f"{heading}: missing row {missing!r}")

    if not allow_incomplete and "Status: NOT SIGNED OFF" in text:
        errors.append("Worksheet still explicitly marked NOT SIGNED OFF")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("worksheet", type=Path, help="operator-owned FIELD_ACCEPTANCE.md")
    parser.add_argument(
        "--allow-incomplete", action="store_true",
        help="check the template/matrix without claiming field acceptance",
    )
    args = parser.parse_args()
    try:
        content = args.worksheet.read_text(encoding="utf-8-sig")
    except OSError as exc:
        parser.error(str(exc))
    errors = validate_worksheet(content, allow_incomplete=args.allow_incomplete)
    if errors:
        for error in errors:
            print("FAIL:", error)
        return 1
    if args.allow_incomplete:
        print("Worksheet structure valid; field tests NOT independently verified.")
    else:
        print("Worksheet claims complete evidence. Human verification still required.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
