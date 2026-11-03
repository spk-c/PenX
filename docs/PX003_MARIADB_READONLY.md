# PX-003 MariaDB saved-session proof (explicit, read-only)

This is an opt-in verifier for an already committed PenX MariaDB
assessment. It extends the existing SQLite-only interactive provenance
check, without modifying normal scanning, migrations, report exports,
user data, MariaDB privileges, or the published release.

## Safety prerequisites

Use a **dedicated database account with SELECT-only privileges** for
the target PenX schema. Provision that account separately through the
database administrator; do not reuse your application's normal write
account or root account. This feature never creates users or grants
privileges.

The verifier refuses non-loopback hostnames/IPs. For an external
MariaDB server, create a secure, explicitly approved local SSH tunnel
and connect the verifier to 127.0.0.1 and the tunnel's forwarded port.
The code does not create a tunnel or connect remotely on its own.
Use the *dedicated* environment variable for the verification password:
it will not read the normal PENX_DB_PASS or configuration credentials.

Optional dependency:

```text
python -m pip install "mysql-connector-python>=9,<10"
```

In PowerShell, provide the secret without typing it into command
history or passing it on the process command line:

```powershell
$env:PENX_VERIFY_MARIADB_PASSWORD = Read-Host "Read-only MariaDB password" -AsSecureString | ConvertFrom-SecureString -AsPlainText
python penx.py evidence verify --session 123 --mariadb-host 127.0.0.1 --mariadb-port 3306 --mariadb-db penx --mariadb-user penx_reader --artifacts "C:\PenX\private-provenance"
Remove-Item Env:\PENX_VERIFY_MARIADB_PASSWORD
```

The secret remains in the process environment temporarily; prefer a
short-lived, restricted session. The command is not automatically run
against any account or production database by PenX.

## What the command does

The Python connector is loaded only after explicit opt-in and strict
validation of local host, port, schema, account and password. The driver
opens one connection with no automatic commits and local-file loading
disabled. Before the first SELECT it requests a server transaction with
`readonly=True`, `isolation_level="REPEATABLE READ"` and
`consistent_snapshot=True`. If the server rejects this read-only
transaction, the connection is closed and the verification fails.

The existing `SessionRepository` reads one consistent saved session.
The standard provenance verifier checks full opted-in UTF-8 source
hashes, quote anchors, original pre-decoding stdout byte hash/length,
and replays the exact formatted recon text to the committed
`summary.raw_scan`. A missing source, partial scan, absent capture,
changed binary file, substituted metadata, or failed transaction
cannot be certified.

On success, the command returns a bounded JSON summary including
`backend: "mariadb-read-only"`. Connection failures and mismatches
return a generic `unverified` JSON status with exit code 2, rather than
printing source bytes, usernames, passwords, SQL statements or driver
errors. There is no scanner execution, model call, database update,
table initialization, schema upgrade or restoration.

## Validation and limits

Offline Python tests use a mocked connector to prove the exact
read-only transaction parameters and failure handling. A separate
CI workflow launches a **disposable local MariaDB service** and
runs a synthetic assessment with a local Python fixture process.
It verifies a round-trip saved session, a read-only UPDATE rejection
and corruption rejection. No external targets are scanned.

This is **internal consistency**, not proof of scanner authenticity
or target permission, and the database/source files are not digitally
signed. Human acceptance on a separately approved Windows/Kali
installation with a least-privilege read-only account remains open.
This work does not implement PX-004 MariaDB backups or restores, nor
does it certify third-party multi-process or transformed scanners.
