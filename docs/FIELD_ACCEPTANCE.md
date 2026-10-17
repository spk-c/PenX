# PenX refactor: repeatable field acceptance

## Offline automated coverage

`tests/test_complete_settings_precedence.py` builds the configuration-key
matrix directly from the keys used by `load_settings` and runs each key
through `METATRON_*`, `PENX_*`, and both namespaces. The typed results must
match the new namespace when both exist; no real environment or user settings
are modified. It also tests .env precedence and simulated Unicode installed
versus portable paths without creating a user-data directory.

## Operator-owned Windows field evidence

On a disposable Windows VM or a machine you explicitly administer, download
the release from the project's official GitHub Release page. Verify its
`SHA256SUMS.txt` through an independently trusted release source, then run:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\collect_refactor_field_evidence.ps1 -InstallerPath "C:\Path\to\PenX-Setup-x64.exe"
```

This **read-only collection step** records the installer SHA-256, project
commit when Git is installed, local OS and Python version and writes a
NOT-RUN worksheet to a new local `refactor-field-evidence` folder. It does
not elevate, start the installer, download dependencies, scan a host, access
customer records, mutate a database or certify any test passed. If a worksheet
already exists, the script fails rather than replacing it.

For each remaining Pk02–Pk12 field gate, use an isolated VM snapshot,
synthetic/disposable target or explicitly approved sanitized backup, capture
command/log/result and mark PASS/FAIL/BLOCKED. In particular, **do not**
rehearse MariaDB migrations against production. Use a consistent backup on a
throwaway local database with separate credentials. No raw scan evidence,
tokens, customer data or personally identifying host information should be
committed to the repository or uploaded to CI.

Maintainers must record the result, environment, immutable commit/build SHA,
expected and actual outcome, evidence locations, and sign-off for each
applicable field scenario **in this document or in a linked, reviewed evidence
record** before claiming 100% completion. Automated checks alone cannot
prove hardware, first-run UAC, actual backup recovery or visual PDF quality.

## Remaining field sign-off checklist

- [ ] Approved Windows target: all 12 scanner choices, scope consent, missing
      dependencies, cancellation, timeouts and descendant cleanup verified.
- [ ] Npcap driver: installation/elevation and non-administrator behavior on
      a disposable Windows machine verified.
- [ ] SQLite WAL and MariaDB: sanitized backups restored to isolated
      databases; migrations, duplicate rejection and rollback checked.
- [ ] Windows installer: first run, upgrade from v0.4.8, repair and uninstall
      on an isolated VM, with user data preserved where promised.
- [ ] Reports: long HTML/PDF/JSON/SARIF reviewed visually and compared;
      interrupted/failed publications recovered or reported accurately.
- [ ] Local LLM: configured endpoint, empty/malformed/timeouts/cancellation
      tested without asserting unverified vulnerabilities.
- [ ] Release: immutable `main` commit, tagged build, SHA-256 verification,
      installer/portable smoke tests and independent maintainer sign-off.

**Status: NOT SIGNED OFF.** A checklist item is not PASS until its evidence
and reviewer are recorded. Only scan hosts that you own or are authorized
to assess.
