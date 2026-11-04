"""PX-104 explicit, read-only, bounded PenX history listing.

No scanner, network, reporting artifact, backup/restore or implicit database
creation. Session targets are redacted unless the operator explicitly opts in.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sqlite3
import stat
from urllib.parse import quote

from penx_app.storage.db_backend import SQLiteConnection
from penx_app.storage.session_repository import SessionRepository


def _readonly_factory(database: str):
    file = Path(database).expanduser().absolute()
    metadata = file.lstat()
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError("History input must be an existing regular SQLite file")
    uri = "file:" + quote(str(file).replace(os.sep, "/"), safe="/:") + "?mode=ro"

    def make_connection():
        # SQLite's URI mode=ro refuses absent files and database writes.
        raw = sqlite3.connect(uri, uri=True, timeout=5)
        try:
            raw.execute("PRAGMA query_only=ON")
        except BaseException:
            raw.close()
            raise
        return SQLiteConnection(raw)
    return make_connection


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="penx history",
        description="Read-only, keyset-paginated SQLite history; targets redacted by default",
    )
    sub = parser.add_subparsers(dest="action", required=True)
    listing = sub.add_parser("list", help="List at most 100 saved session headers")
    listing.add_argument("--sqlite-db", required=True,
                         help="Explicit existing SQLite database (never created)")
    listing.add_argument("--limit", type=int, default=50)
    listing.add_argument("--before-id", type=int, default=None)
    listing.add_argument("--status", choices=("active", "pending"), default="active")
    listing.add_argument("--target", help="Optional exact target match; not echoed")
    listing.add_argument("--from-date", default=None, help="Inclusive YYYY-MM-DD")
    listing.add_argument("--until-date", default=None, help="Inclusive YYYY-MM-DD")
    listing.add_argument("--show-target", action="store_true",
                         help="Explicitly print sensitive saved targets")
    try:
        args = parser.parse_args(argv)
    except SystemExit:
        return 2
    try:
        page = SessionRepository(_readonly_factory(args.sqlite_db)).history_page(
            limit=args.limit, before_id=args.before_id, status=args.status,
            target=args.target, from_date=args.from_date, until_date=args.until_date,
        )
    except (OSError, sqlite3.Error, ValueError, TypeError):
        print(json.dumps({"status": "unavailable",
                          "error": "history-query-failed"}))
        return 2
    output = {
        "schema": "penx-history-page-v1",
        "status": "ok",
        "entries": [
            {"session_id": row.session_id,
             "target": row.target if args.show_target else "[redacted]",
             "scan_date": row.scan_date,
             "status": row.status}
            for row in page.entries
        ],
        "count": len(page.entries),
        "next_before_id": page.next_before_id,
        "has_more": page.next_before_id is not None,
        "target_redacted": not args.show_target,
        "target_filter_applied": args.target is not None,
        "note": "Read-only keyset page, not a stable cross-page snapshot.",
    }
    print(json.dumps(output, ensure_ascii=True, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
