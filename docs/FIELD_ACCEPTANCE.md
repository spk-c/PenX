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

To compare the installer with a digest obtained from an **independently trusted**
release source, supply the optional `-ExpectedInstallerSha256` argument. A
mismatch fails **before creating the acceptance worksheet**. The collector
rejects directories and reparse-point installer paths. An exact match is
recorded as `MATCHED OPERATOR PIN; ORIGIN NOT AUTHENTICATED` and a missing pin as
`NOT PROVIDED`. This is byte-identity checking, not Authenticode verification,
proof of an independent release source, or human field sign-off.

```powershell
$trustedSha256 = "<independently-verified-64-hex-digest>"
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\collect_refactor_field_evidence.ps1 `
  -InstallerPath "C:\Path\to\PenX-Setup-x64.exe" -ExpectedInstallerSha256 $trustedSha256
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

**Active operator follow-up:** [#187 Windows/Kali/Npcap/installer and report matrix](https://github.com/spk-c/PenX/issues/187) and [#188 isolated database provenance/recovery](https://github.com/spk-c/PenX/issues/188). Closing the earlier #81/#82 tracker issues was administrative, not independent validation.

**Status: NOT SIGNED OFF.** A checklist item is not PASS until its evidence
and reviewer are recorded. Only scan hosts that you own or are authorized
to assess.

## Kali Linux field evidence

The same read-only collector also emits two **Kali** sections so a Linux
field run can be recorded in the operator-owned worksheet:

- **Kali loopback scanner matrix** — the 12 adapter choices (1–9, s, c, d)
  plus the separately opted-in endpoint mapper (e), exercised against owned
  loopback fixtures only (no external targets, no passive provider calls).
- **Kali build, packaging and restore matrix** — Debian build/install, XDG
  config mode `0600`, remove/reinstall config preservation, WHOIS
  `python-whois` frozen-bundle data, SQLite WAL kill/`integrity_check`,
  local-model assessment, and long/short report pagination.

Each Kali row carries its own **OS / arch / kernel** provenance column plus
the tool/build/backup SHA-256, expected/actual outcome, sanitized evidence
and independent reviewer/date. A `PASS` row is rejected unless every one of
those provenance columns is filled in.

The Kali sections are **optional**: a Windows-only worksheet may omit them
entirely and still validates. Once a Kali section is present, it is fully
validated (no missing rows, no duplicates, valid statuses, and no `PASS`
without complete provenance). Running the Kali loopback suite
(`tests/kali_local_scanner_acceptance.py`) is a practical smoke, not a sign-off;
it must pass on a disposable Kali VM against loopback fixtures before any row
is marked `PASS`.

## Issue #81/#82 evidence worksheet validation

The read-only collector also creates separate rows for the **12 full-preset
scanner modes** (1–9, s, c, d), the separately opted-in endpoint mapper (e),
Windows consent/cancellation/Npcap cases and restore/upgrade/report scenarios.
All rows start as `NOT RUN`; the script does not inspect or operate any
production environment.

After carrying out the checks on a disposable Windows VM and filling in the
expected/actual results, tool/build/backup SHA-256 hashes, approved target,
rollback details, sanitized evidence and independent reviewer/date:

```powershell
python .\scripts\validate_field_acceptance.py .\refactor-field-evidence\FIELD_ACCEPTANCE.md
```

To check the **uncompleted template's structural completeness**, use
`--allow-incomplete`. This accepts `NOT RUN`, `FAIL` and `BLOCKED`
but still rejects a `PASS` with missing provenance, missing scenario IDs,
duplicate rows and invalid statuses. It does **not** sign off testing.
A structurally complete `PASS` record still needs human review of the
actual, local evidence. Never treat a CI-generated worksheet or a filled
table alone as proof of hardware tests. Upload only sanitized summaries;
keep original VM images, logs and backups in private operator-controlled storage.

