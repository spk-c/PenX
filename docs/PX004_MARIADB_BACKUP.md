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


## Restore acceptance and remaining work

PenX does **not** offer a MariaDB in-place restore command. The new
GitHub Actions test restores the generated dump only into a freshly
created, isolated scratch database and checks a synthetic saved
assessment and database uniqueness index, then tests corruption.

A production-safe restore still needs pre-restore backup, explicit
target/database approval, maintenance/connection locks, deterministic
partial-import recovery, rollback and independent operator rehearsal.
No real user database has been modified for this development slice.
