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

A maintainer must review evidence and sign `docs/REFACTOR_ACCEPTANCE.md`
before claiming 100% complete. Automated checks alone cannot prove hardware,
first-run UAC, actual backup recovery or visual PDF quality.
