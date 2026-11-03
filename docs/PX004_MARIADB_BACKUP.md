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

## Restore acceptance and remaining work

PenX does **not** offer a MariaDB in-place restore command. The new
GitHub Actions test restores the generated dump only into a freshly
created, isolated scratch database and checks a synthetic saved
assessment and database uniqueness index, then tests corruption.

A production-safe restore still needs pre-restore backup, explicit
target/database approval, maintenance/connection locks, deterministic
partial-import recovery, rollback and independent operator rehearsal.
No real user database has been modified for this development slice.

