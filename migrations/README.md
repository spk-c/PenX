# Optional MariaDB schema setup (Issue #40)

**Default PenX / SQLite:** No manual migrations. The SQLite schema is
created and upgraded automatically on startup.

**MariaDB mode is optional:** MariaDB does **not** automatically create the
tables, and it is **not** interchangeable with SQLite. Back up your existing
database before applying migrations or changing the backend.

## Fresh MariaDB installation

1. Install MariaDB and the optional Python connector `mysql-connector-python`.
2. Create the database and a least-privilege application account using the
   MariaDB client (replace example credentials with your own):

   ```sql
   CREATE DATABASE penx CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
   CREATE USER 'penx'@'localhost' IDENTIFIED BY 'CHOOSE_A_STRONG_PASSWORD';
   GRANT SELECT, INSERT, UPDATE, DELETE ON penx.* TO 'penx'@'localhost';
   ```

3. In a MariaDB client account with **schema alteration permissions**, run
   these files **in exactly this order** from the PenX repository root. In
   the interactive `mariadb` or `mysql` client, `USE penx;` first:

   ```sql
   SOURCE migrations/001_baseline.sql;
   SOURCE migrations/002_evaluations.sql;
   SOURCE migrations/003_confidence.sql;
   SOURCE migrations/004_learned_rules.sql;
   SOURCE migrations/005_runtime_compat.sql;
   SOURCE migrations/006_scanner_metadata.sql;
   SOURCE migrations/007_summary_unique.sql;
   ```

4. Configure `PENX_DB_ENGINE=mariadb` and `PENX_DB_HOST`,
   `PENX_DB_USER`, `PENX_DB_PASS`, `PENX_DB_NAME` in a private
   `.env`. Run `python penx.py --check` to inspect your installation.

`001_baseline.sql` creates the six original core tables, `002` adds
evaluations and `summary.model_name`, `003` adds vulnerability confidence,
`004` adds learned rules, and `005` ensures the history status column
needed for **pending** versus **active** scan sessions also exists on
legacy installations.

## Upgrading an existing MariaDB database

First take a backup (for example with `mariadb-dump`). You may apply these
files in the same order: `CREATE TABLE IF NOT EXISTS` and
`ADD COLUMN IF NOT EXISTS` retain existing data. The scripts **do not**
remove old columns or automatically rewrite incompatible custom schemas. A
very old or independently modified database may need a reviewed migration
before the app can run; verify table columns with `SHOW COLUMNS FROM history`
and similarly for `summary` and `vulnerabilities`.

These SQL scripts are intentionally **not** run automatically by PenX.
Do not paste database passwords into public bug reports.

## Issue #147: summary uniqueness and legacy data safety

**Before upgrading either database backend:** take a consistent backup and
verify its restore using a copy. **No automated deduplication is performed.**
A duplicate assessment may have associated vulnerability/evaluation records;
choosing a "winner" or deleting one can silently lose customer data.

SQLite upgrades automatically from schema version 0–2 to **version 3** on
startup. Version 3 installs `uq_summary_sl_no` and triggers requiring a
non-NULL, existing `history.sl_no` on future inserts/updates. The migration
runs in a single transaction. If duplicate, NULL or orphan summary rows exist,
it aborts and rolls back *all* changes, including the schema version. Resolve
these records on a **restored backup copy** before retrying. To inspect an old
SQLite database without opening it through PenX, run:

```powershell
python scripts/audit_summary_uniqueness.py --sqlite "C:\path\to\penx.db"
```

This audit opens SQLite read-only and prints session IDs, summary row IDs and
counts, never scan text or AI analysis. For MariaDB, run these **read-only**
queries *before* applying `007_summary_unique.sql`:

```sql
SELECT sl_no, COUNT(*) AS copies FROM summary
GROUP BY sl_no HAVING COUNT(*) > 1;
SELECT id FROM summary WHERE sl_no IS NULL;
SELECT s.id, s.sl_no FROM summary AS s
LEFT JOIN history AS h ON h.sl_no = s.sl_no
WHERE h.sl_no IS NULL;
```

If any query returns rows, STOP: inspect a backup and reconcile affected
sessions explicitly. Preserve all summary/finding/evaluation rows until the
correct assessment is established; do not delete or merge by timestamp alone.
Migration `007_summary_unique.sql` changes `summary.sl_no` to `NOT NULL`
and adds a named UNIQUE index. MariaDB rejects duplicates; do not use
`ALTER IGNORE`. The ALTER statement is designed to be repeatable on a clean
database; test it first on a restored copy. The MariaDB application account
still requires only DML privileges; apply DDL manually with an administrator.

## Refactored runtime: trusted scanner metadata

SQLite schema version 2 added `summary.scan_metadata` transactionally. MariaDB
requires `006_scanner_metadata.sql` before starting this version. The field
stores a versioned adapter-status document, separate from raw scanner text.
Existing rows have empty metadata and retain the conservative legacy reader;
no historical evidence or successful scanner status is invented.

Take a consistent backup before upgrading (SQLite backup API for an active WAL
database; `mariadb-dump` for MariaDB), and verify its restore on a copy. The
migration is additive. Do not decrease SQLite `user_version` to bypass version
checks. To roll back, restore the pre-upgrade backup with the corresponding
application version. No automatic destructive down migration is provided.
