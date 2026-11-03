# Verified backup/restore (PX-004)

PenX stores scan history and evidence locally in SQLite (default) or,
optionally, MariaDB. Upgrades, disk failures and interrupted runs must not
destroy that history. The `penx backup` command provides verified backups,
a restore preview, and an explicit, user-approved restore.

## Backup format

A backup is a **file pair**:

```
penx-backup-20261103-121530-a1b2c3d4.sqlite   database copy
penx-backup-20261103-121530-a1b2c3d4.json    metadata manifest
```

The manifest contains metadata only: schema, status, file name, creation
time, source schema version, size and SHA-256 digest. No scan data, target
names or other content is stored in the manifest.

A backup is **valid** only when all of the following hold:

- the manifest parses and carries `status: verified` for exactly this file,
- the database file exists,
- its size and SHA-256 match the manifest,
- `PRAGMA integrity_check` passes,
- its schema version is not newer than the one this PenX build understands.

A crash or interrupt can leave a `.tmp` file or a manifest without its
database file behind; neither state passes verification.

## Commands

Run through the PenX entrypoint (`penx.py`, `PenX.exe`, or `penx` on PATH):

```bash
# Create a verified backup of the configured database
penx backup create

# Verify any backup pair (file, manifest, or directory with the latest pair)
penx backup verify --file <path>

# Inspect a backup and dry-run the migration without touching the live DB
penx backup preview --file <path>

# Explicitly restore a verified backup over the live database
penx backup restore --file <path> --confirm
```

Options:

- `--db <path>`: use a specific SQLite file instead of the configured one
  (required when the engine is `mariadb`).
- `--output-dir <dir>`: backup destination (default: `<data>/backups`), and
  for `restore`, where the mandatory pre-restore backup is written.

Exit codes: `0` success, `1` backup invalid or migration dry run failed,
`2` usage/storage/restore error (nothing was replaced).

## Restore behavior

`penx backup restore` is deliberately conservative:

1. The backup is verified first; an invalid backup changes nothing.
2. If the live database exists, it is itself backed up first (mandatory
   pre-restore backup, written to the backup directory).
3. The replacement is staged as a temporary file in the same directory,
   migrated to the current schema and integrity-checked before it is moved
   into place with an atomic rename.
4. If any step fails, the live database is left byte-identical (or absent,
   if it did not exist before).

PenX-managed SQLite connections now hold an OS-level shared lock for their
lifetime. Restore acquires an exclusive OS lock before copying or replacing
files, and fails closed if any managed connection is still open. It also
prevents new managed PenX connections from opening during the replacement.
**Stop PenX and any other SQLite client before restore:** external clients
that bypass the PenX lock do not participate. Do not restore a database
on a network filesystem without verified file-locking semantics.

Restore never overwrites the live database in place, and it is never
performed without the explicit `--confirm` flag.

The migration dry run (`preview`) happens on a throwaway copy, so the
backup's bytes and hash are guaranteed unchanged even when the migration
would fail (for example, a legacy v2 database with duplicate summary rows
blocks the v3 migration until the rows are reconciled).

## MariaDB

Existing `penx backup create/verify/preview/restore` operations remain **SQLite-only**.
Separate opt-in `mariadb-create`, `mariadb-verify` and `mariadb-preview`
commands are documented in [PX004_MARIADB_BACKUP.md](PX004_MARIADB_BACKUP.md).
A MariaDB logical dump is an unencrypted SQL file with a hash-bound manifest;
verification is **file integrity only**. In-place MariaDB restoration is not
implemented; the CI restores solely into a fresh, isolated test schema.

## Recommended upgrade workflow

```bash
penx backup create                       # before updating
penx backup verify --file <backup.sqlite>
# ... apply the update; if something goes wrong:
penx backup preview --file <backup.sqlite>   # inspect + migration dry run
penx backup restore --file <backup.sqlite> --confirm
```
