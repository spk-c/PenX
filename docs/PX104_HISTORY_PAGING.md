# PX-104 — Read-only paged local scan history (first slice)

**Availability:** only in source after this change; this is a **partial PX-104**
implementation, not the full workspace/batch history milestone. No new
database columns, indexes, migrations, export format, network requests, scan
work or background jobs are introduced.

## Usage

~~~powershell
python penx.py history list --sqlite-db "C:\\PenX\\data\\penx.sqlite3" --limit 50
python penx.py history list --sqlite-db "C:\\PenX\\data\\penx.sqlite3" --limit 50 --before-id 1200
python penx.py history list --sqlite-db "C:\\PenX\\data\\penx.sqlite3" --target "example.test" --from-date 2026-11-01 --until-date 2026-11-04
~~~

The SQLite input path must be an **existing regular local file**, not a
symbolic link. The command uses SQLite's `mode=ro` and `query_only`, does
not initialize/migrate a database, and never reads stored raw scanner output,
LLM analysis, evidence artifact files or other tables. The optional exact
target filter is parameterized and not included in the report.

Each response is a `penx-history-page-v1` JSON object. Rows contain only the
numeric session ID, scan date, status, and **`[redacted]` target** by default.
Explicit `--show-target` reveals sensitive target names to stdout; don't use
it in shared logs. `--status pending` is an intentional request to list
unfinished sessions (the default lists only `active`).

The page size is 1..100 (default 50). `next_before_id` may be provided as
`--before-id` to retrieve the following older page. No OFFSET is used:
the query reads at most `limit + 1` session headers, ordered by descending
primary-key session ID. Newer inserted records do not shift the next page;
**concurrent changes/deletions still mean pages are not an atomic snapshot**.
The CLI returns `status: unavailable` and a generic error on malformed
filters/missing/corrupt SQLite, without printing paths or sensitive data.

This is a SQLite-only view. It does **not** implement linked project
dashboards, scanner/evidence/confidence filters, MariaDB history listing,
materialized batch summaries, or PX-102 durable jobs. Those remain blocked or
pending. The original interactive history view and `get_all_history` API
are untouched for backward compatibility.

## Tests and acceptance boundaries

The deterministic fixture seeds 10,000 sessions and checks keyset ordering,
non-overlapping pages, active/pending separation, exact Unicode/date filters,
malicious SQL parameter strings, invalid dates/cursors/sizes, redaction,
file/symlink rejection, absence of scans or network work, and no
`summary.raw_scan` or artifact reads.

An existing SQLite live database may change while the read query executes:
there is no signed snapshot or operator field sign-off. Only print target
names when their disclosure is authorized.
