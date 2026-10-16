#!/usr/bin/env python3
"""Read-only, non-destructive SQLite audit for PenX issue #147.

Only identifiers and counts are printed: never raw scan or AI text.
Use this script on old databases *before* launching a newer PenX build.
"""
from __future__ import annotations

from contextlib import closing
import argparse
from pathlib import Path
import sqlite3


def audit_database(path: Path) -> dict[str, list[tuple]]:
    """Inspect a database read-only, including WAL, without modifying schema."""
    uri = path.resolve().as_uri() + "?mode=ro"
    with closing(sqlite3.connect(uri, uri=True, timeout=10)) as conn:
        tables = {
            row[0] for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        if not {"summary", "history"} <= tables:
            raise ValueError("Database has no PenX summary/history tables")
        return {
            "duplicates": conn.execute(
                "SELECT sl_no, COUNT(*) FROM summary GROUP BY sl_no "
                "HAVING COUNT(*) > 1 ORDER BY sl_no LIMIT 100"
            ).fetchall(),
            "null_session_ids": conn.execute(
                "SELECT id FROM summary WHERE sl_no IS NULL "
                "ORDER BY id LIMIT 100"
            ).fetchall(),
            "orphan_summaries": conn.execute(
                "SELECT s.id, s.sl_no FROM summary AS s "
                "LEFT JOIN history AS h ON h.sl_no = s.sl_no "
                "WHERE s.sl_no IS NOT NULL AND h.sl_no IS NULL "
                "ORDER BY s.id LIMIT 100"
            ).fetchall(),
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sqlite", type=Path, required=True,
                        help="Existing PenX SQLite file to inspect (read-only)")
    options = parser.parse_args(argv)
    try:
        results = audit_database(options.sqlite)
    except (sqlite3.Error, OSError, ValueError) as exc:
        print(f"[FAIL] Cannot safely audit database: {exc}")
        return 1
    for category, rows in results.items():
        print(f"{category}: {len(rows)} finding(s) (first 100 at most)")
        for row in rows:
            print(f"  {row!r}")
    if any(results.values()):
        print("[BLOCKED] Back up and reconcile rows manually before migration.")
        return 2
    print("[OK] No summary uniqueness/null/orphan anomalies detected.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
