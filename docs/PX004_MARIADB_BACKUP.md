# PX-004: Native MariaDB logical backup

This is an **opt-in** backup / verification slice, not a background backup
service or a production restore tool. Existing SQLite restore is unchanged.

## Preparation and secure storage

Install the optional Python connector (mysql-connector-python 9.x) and the
official MariaDB client with the `mariadb-dump` binary. Use a dedicated
SELECT-only account, an existing private local output directory, and a
localhost/127.0.0.1 endpoint (or a separately approved local SSH tunnel).

The SQL contains **unencrypted scan and assessment data**. Store it on
encrypted local storage with strict file permissions; never in public
repositories, webroots or publicly synced folders. The password is passed
only through a temporary child environment variable, not on the command
line; privileged administrators may still inspect process environments.

## Explicit commands

~~~powershell
New-Item -ItemType Directory "C:\PenX\private-backups" -Force
$env:PENX_MARIADB_BACKUP_PASSWORD = Read-Host "Dedicated backup password" -AsSecureString | ConvertFrom-SecureString -AsPlainText
python penx.py backup mariadb-create --host 127.0.0.1 --port 3306 --database penx --user penx_backup_reader --output-dir "C:\PenX\private-backups"
Remove-Item Env:\PENX_MARIADB_BACKUP_PASSWORD
~~~

The command returns JSON with the actual SQL filename. Replace the example
below with that exact filename:

~~~powershell
python penx.py backup mariadb-verify --file "C:\PenX\private-backups\penx-mariadb-ACTUAL.sql"
python penx.py backup mariadb-preview --file "C:\PenX\private-backups\penx-mariadb-ACTUAL.sql"
~~~

Verify and preview are offline. They never contact MariaDB or execute SQL.

## What is and is not verified

Preflight requires the expected PenX tables, **InnoDB** storage, and a
read-only database snapshot before starting the native logical dump.
The dump runs with a single transaction and no table locks. It excludes
stored routines, events and triggers: standard PenX migrations create
none, but custom extensions need separate backups.

Each successful result has a non-overwriting `.sql` file and adjacent
versioned `.json` manifest with source schema name, table names, size
and SHA-256. Failed or too-large dumps (currently above **512 MiB**)
are rejected. A crash may leave temporary/orphan files, but they cannot
be verified without a complete manifest.

The result `verified-file-integrity-only` means hashes and metadata
match, **not** that the executable SQL is authentic, semantically valid
or guaranteed to restore. A forged dump and forged manifest can match.
The preview explicitly returns `restore_available: false`.

## External SQL + manifest SHA-256 pins (PX-004; offline identity only)

The adjacent `.sql` and `.json` files can be **forged together**, so their
matching internal hashes are not proof of a genuine backup. If an operator
records **both original hashes out-of-band at a trusted time** (e.g. in a
separate immutable evidence ledger), this additional opt-in command checks
that the two existing files still match those previously retained values.

~~~powershell
$sql = "C:\\PenX\\private-backups\\YOUR-BACKUP.sql"
$manifest = [System.IO.Path]::ChangeExtension($sql, ".json")
# Run these two commands only on the original verified pair; record BOTH
# digest values in a separate controlled location, not beside the pair:
(Get-FileHash -LiteralPath $sql -Algorithm SHA256).Hash.ToLowerInvariant()
(Get-FileHash -LiteralPath $manifest -Algorithm SHA256).Hash.ToLowerInvariant()

# Supply the TWO values previously captured and stored independently:
python penx.py backup mariadb-verify-pinned --file $sql --sql-sha256 YOUR_64_HEX_SQL_HASH --manifest-sha256 YOUR_64_HEX_MANIFEST_HASH
~~~

The command accepts lowercase, exactly 64-character SHA-256 values only.
It compares the entire SQL dump (up to the existing **512 MiB** cap) and
bounded manifest (**16 KiB**) against their independent pins. If either file
is changed but its companion JSON/SQL hash is also rewritten, the previously
recorded pin prevents the modified pair from passing. Malformed digest
arguments, symlinks and mismatched or missing files cause generic failure.

Every successful result is labelled
`status: operator-pinned-file-identity-only`, with
`pin_origin_authenticated: false`,
`historical_backup_rows_verified: false`,
`sql_semantics_verified: false`, `restore_available: false` and
`sql_executed: false`. A malicious or incorrect *original* pair could have
been pinned, and attacker-supplied new pins prove nothing about origin.
There are no signatures, external notarization, DB accesses or SQL imports.
The before/after manifest hash checks are **not atomic file locking**;
protect the original backups from adversarial concurrent replacement.

## New: non-executable scratch restore plan

The `mariadb-restore-plan` subcommand accepts a verified backup and a
proposed `penx_restore_<32 lowercase hex>` scratch database name:

~~~powershell
python penx.py backup mariadb-restore-plan --file "C:\PenX\private-backups\YOUR-BACKUP.sql" --target-schema penx_restore_0123456789abcdef0123456789abcdef
~~~

It returns a deterministic SHA-256 plan identity linking the backup
digest to the proposed destination. **It never connects to MariaDB,
checks target existence, starts a maintenance lock, creates tables, or
executes SQL.** It explicitly returns `restore_available: false`,
`target_existence: not-checked` and `sql_semantics_verified: false`.
The plan can be invalidated by later backup changes; a future
implementation must reverify the backup and server state at execution.

A separate CI-only aborted-import test uses a fixed scratch schema,
deliberately causes an SQL error after a table is created, verifies that
the source database remains unchanged, and removes **only** that known
disposable scratch schema. It demonstrates why SQL imports cannot be
treated as atomic rollback. No user database is modified.

## Read-only server-side scratch target preflight

An optional **second**, explicitly requested check connects to MariaDB
using the existing PX-003 read-only connector. It validates the backup
SHA and proposed target, then confirms whether the name was visible as
absent in a single server-enforced READ ONLY snapshot. The login schema
must match the manifest's source database.

This requires an intentionally provisioned account with **direct global
SHOW DATABASES permission** as well as read access to the existing
source schema. Without that global metadata permission, MariaDB can
hide other schemas from the query; therefore the command rejects the
check instead of claiming a missing target is safe. This permission
reveals all database names and must **not** be granted automatically.
Review its disclosure impact and use a separate temporary account if
an operator chooses to run this preflight.

Use the existing separate password variable for read-only verification
and a loopback-only endpoint (or separately approved SSH tunnel):

~~~powershell
$env:PENX_VERIFY_MARIADB_PASSWORD = Read-Host "Read-only preflight password" -AsSecureString | ConvertFrom-SecureString -AsPlainText
python penx.py backup mariadb-restore-preflight --file "C:\PenX\private-backups\YOUR-BACKUP.sql" --target-schema penx_restore_0123456789abcdef0123456789abcdef --host 127.0.0.1 --port 3306 --database penx --user penx_metadata_reader
Remove-Item Env:\PENX_VERIFY_MARIADB_PASSWORD
~~~

The result is **never** restore authorization. Even a successful check
means only `absent-at-check-time-only`; it neither reserves the name
nor checks permissions to create the target, SQL safety, maintenance
state, pre-restore backup or future race conditions. It returns
`target_reserved: false` and `restore_available: false`.
The existing offline `mariadb-restore-plan` is unchanged and remains
available without a database connection.

On a disposable MariaDB CI service, tests verify that an account
without global schema visibility cannot certify target absence,
that explicitly granted metadata visibility permits an absent-name
snapshot, and that the same snapshot check refuses the target after
it is created. **The CI-only grant does not apply to user databases.**

## Read-only post-import scratch comparison

After an operator independently creates a scratch database and imports a
trusted dump, the separate `mariadb-restore-audit` command compares
the **current** source database and the scratch database using two
server-enforced `READ ONLY` transactions. It checks that the exact
manifest-listed InnoDB tables exist on both sides, then compares column
definitions, indexes and per-table row counts. No individual assessment
row or raw scanner text is printed.

Use two explicit, separate SELECT-only accounts. The source password
comes only from `PENX_VERIFY_MARIADB_PASSWORD`, the scratch password
only from `PENX_SCRATCH_AUDIT_PASSWORD`. The host must be loopback
(or an already approved local tunnel). The target name remains limited to
`penx_restore_<32 lowercase hex>`:

~~~powershell
$env:PENX_VERIFY_MARIADB_PASSWORD = Read-Host "Source reader password" -AsSecureString | ConvertFrom-SecureString -AsPlainText
$env:PENX_SCRATCH_AUDIT_PASSWORD = Read-Host "Scratch reader password" -AsSecureString | ConvertFrom-SecureString -AsPlainText
python penx.py backup mariadb-restore-audit --file "C:\PenX\private-backups\YOUR-BACKUP.sql" --target-schema penx_restore_0123456789abcdef0123456789abcdef --host 127.0.0.1 --port 3306 --source-user penx_source_reader --target-user penx_scratch_reader
Remove-Item Env:\PENX_VERIFY_MARIADB_PASSWORD
Remove-Item Env:\PENX_SCRATCH_AUDIT_PASSWORD
~~~

Success returns `observed-read-only-structural-parity` with a hash of
observed schema metadata and aggregate row counts. Every result
explicitly states `restore_available: false`,
`snapshot_contents_verified: false` and
`historical_backup_rows_verified: false`. Identical table counts
**do not prove equal records**, and live source data may have changed
since the dump. These are two separate read-only database snapshots,
not a cross-server atomic snapshot or a semantic SQL validation.

CI restores a generated dump into a disposable scratch schema, verifies
this parity, modifies only the scratch table definition and proves
that the audit then fails closed. Neither the CLI nor the audit module
performs an import, creation or cleanup of any user database.


## Opt-in bounded row-content comparison

The existing post-import command now offers **`--verify-content`**.
Without it, the original structure-and-row-count comparison is unchanged.
With it, PenX also reads row values within each of the two server-enforced
`READ ONLY` snapshots and compares per-table SHA-256 multisets, preserving
duplicates while ignoring SQL result order:

~~~powershell
python penx.py backup mariadb-restore-audit --file "C:\PenX\private-backups\YOUR-BACKUP.sql" --target-schema penx_restore_0123456789abcdef0123456789abcdef --host 127.0.0.1 --port 3306 --source-user penx_source_reader --target-user penx_scratch_reader --verify-content
~~~

Before running, configure the **same two dedicated, separate password
environment variables** described above. This command is deliberately
opt-in because it reads sensitive row contents **into local process
memory**. Neither row contents nor per-row/table hashes are printed,
saved or returned. Unknown connector data types, nonfinite numbers,
incomplete reads and resource overruns fail closed. The fixed limits
are **2,000 rows per table, 10,000 rows total, 256 KiB per field,
512 KiB per row and 32 MiB encoded content per database side**.
The read-only source/scratch accounts need SELECT on all relevant
tables. Run only from a trusted local host.

A successful comparison reports
`observed-read-only-content-parity` and
`current_row_multiset_compared: true`, but still sets
`restore_available: false` and
`historical_backup_rows_verified: false`. Only the **current rows
observed in two separate read-only snapshots** are compared.
It is not an atomic cross-schema snapshot, a digital signature,
a comparison against the historical dump's actual row data, or a
replacement for stopping writes and rehearsing a restore. Identical
row hashes have a negligible but nonzero collision probability.

The isolated MariaDB CI validates a successful content comparison,
changes one field in **scratch only** while retaining the same row
counts and schema, confirms that structural-only audit still passes
but content audit fails, then restores that CI-only value and checks
success again. No production data is modified.

## Offline SQL dump diagnostics (PX-004; not a restore authorization)

The opt-in command below checks a **hash-matching local backup pair** and
inspects at most **8 MiB of its UTF-8 SQL text** for generic red flags:

~~~powershell
python penx.py backup mariadb-dump-inspect --file "C:\\PenX\\private-backups\\YOUR-BACKUP.sql"
~~~

The diagnostic reports only SHA-256, byte and table counts, and generic
`risk_flags`. It never echoes SQL statements, raw scan records or schema
names, contacts MariaDB, or executes a subprocess. **Every successful
diagnostic reports `status: manual-review-required`,
`sql_semantics_verified: false`, `historical_backup_rows_verified: false`,
`sql_executed: false` and `restore_available: false`.** Even an empty
`risk_flags` list does not mean the SQL is safe or executable.

Flags are conservative, lexical indicators, *not a SQL grammar, allowlist or
completeness proof*. They include executable/versioned comments, client
`DELIMITER`/`SOURCE`, cross-schema references, unexpected write/privilege
statements, charset/session settings, missing/duplicate/unlisted table DDL,
out-of-order INSERT targets and an unobserved completion footer. Some
**ordinary** `mariadb-dump` files contain versioned executable comments;
they are flagged for manual review, not rejected as definitely malicious.
A missing `-- Dump completed on ...` line is **not** definitive truncation:
the dump client can omit it when comments are disabled. The scanner also
reports `unfinished-sql-statement` when SQL remains after the last
non-quoted semicolon, `unterminated-quoted-token` for unclosed single,
double or backtick quotes, and `unterminated-block-comment` for a
truncated `/* ... */` comment. It ignores apparent semicolons inside
quoted strings/identifiers or normal SQL comments; the check uses bounded,
single-pass state tracking. Common doubled quotes and MariaDB dump
backslash escapes are handled, but **SQL modes such as
`NO_BACKSLASH_ESCAPES`, client directives and unusual statements are not
fully interpreted**. These flags indicate only possible truncation,
not complete SQL syntax validation.

Text inside quoted rows can cause a conservative false positive; conversely,
crafted SQL can evade lexical patterns. The tool does **not** verify
individual historical row values against the saved dump. It never reports
a pass or authorizes restore merely because there are no lexical flags.

Malformed UTF-8, binary controls, mismatched hashes, unverified manifests,
files above 8 MiB, lines above 64 KiB, or over 100,000 lines make this
optional diagnostic fail closed (CLI status 2). Ordinary hash-only
`mariadb-verify` and `mariadb-preview` remain available for larger dumps,
but neither proves SQL semantics. The diagnostic's double hash/read is not
an atomic lock against concurrent adversarial file modification; keep offline
copies private and immutable, and separately validate restores only on
approved disposable scratch databases.

Tests use bounded synthetic SQL and the *actual* `mariadb-dump` output from
the disposable MariaDB CI container. No actual user data or restoration is
performed by this command.

## Restore acceptance and remaining work

PenX does **not** offer a MariaDB in-place restore command. The new
GitHub Actions test restores the generated dump only into a freshly
created, isolated scratch database and checks a synthetic saved
assessment and database uniqueness index, then tests corruption.

A production-safe restore still needs pre-restore backup, explicit
target/database approval, maintenance/connection locks, deterministic
partial-import recovery, rollback and independent operator rehearsal.
No real user database has been modified for this development slice.
