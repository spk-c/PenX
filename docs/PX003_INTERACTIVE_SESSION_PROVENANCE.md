# PX-003: Interactive saved-session source verification

**Scope:** An opt-in, *synthetic-tested* first slice for interactive scanner
selection and an existing SQLite assessment history. This is not a release,
an independent user-data field acceptance, or a guarantee that every scanner
adapter produces an exact stdout proof.

## Explicit local opt-in before starting PenX

Keep original scanner output in a private directory. On Windows PowerShell:

```powershell
$env:PENX_RAW_ARTIFACT_DIR = "C:\PenX\private-provenance"
python penx.py
```

Choose an authorized target, then use the normal interactive scanner menu.
The setting already enabled bounded UTF-8 scanner text retention at
assessment-save time. It now also enables per-adapter capture of original
subprocess stdout bytes *before* model analysis when one complete,
untransformed, stdout-only process can be safely associated with the
adapter's final output. Without this environment variable, there is no new
binary capture. The accepted source proof travels through `ReconText`,
the assessment service, and the version-3 `scan_metadata` field in the
existing summary row. No database migration or new scanner mode is needed.

**Sensitive content:** Captures may include server banners, domains,
credential fragments, and other private information. Restrict access to
the chosen directory. If a scan is canceled or the local model/storage
later fails, already opted-in captured byte files may still exist even
without a committed history row; their cleanup is operator-managed.

## Offline SQLite session check

Specify the existing database explicitly and the actual saved session ID:

```powershell
python penx.py evidence verify --session 123 --sqlite-db "C:\path\to\penx.sqlite" --artifacts "C:\PenX\private-provenance"
```

The verifier opens only an existing SQLite file using `mode=ro` plus
`PRAGMA query_only=ON`. No scanner is executed; no model request is
sent; migrations are not run. The original committed SQLite session is
loaded through `SessionRepository` with its consistent read snapshot.

To receive `verified-retained-integrity` for a session, all selected
adapters must have COMPLETE outcomes and individually saved UTF-8
sources; there must be at least one bound pre-decoding stdout byte proof.
The validator rechecks each saved adapter's text digest, quote anchors,
and original .bin bytes, then reconstructs the exact formatted scanner
recon text and compares it with the stored session summary's `raw_scan`.
A missing/changed file, forged digest, altered DB summary, incomplete
adapter or historical record without saved original output fails closed.
Successful output is a small JSON summary with session ID, source/byte
counts and `session_raw_text_verified: true`. It never prints raw scanner
text. On failure it returns a generic unverified result with exit code 2.

This is a consistency/integrity check, *not* proof of target ownership,
scanner execution identity, model accuracy, vulnerability applicability,
or document authenticity. It has **no digital signature**, and a hostile
party who controls the database and files could replace them together.
The reconstructed recon check deliberately does not certify partially
saved sessions with failed/unretained adapters.

## Boundaries and remaining work

- Local fixture tests use a temporary SQLite database, Python-only
  subprocesses and fake model responses, with no external scans.
- The interactive path uses the existing environment opt-in. No capture
  is performed in passive-only collection or when a user cancels scanner
  selection before dispatch.
- This SQLite-specific CLI intentionally does not invoke the normal
  `get_connection` path because that path can initialize/migrate SQLite.
  MariaDB now has a separate, explicitly opt-in loopback-only
  read-only verifier (see `PX003_MARIADB_READONLY.md`), with
  isolated CI integration; human field sign-off remains open.
- Multi-process, mixed stdout/stderr, transformed, and native Python
  network adapter results are not retroactively attested as exact
  subprocess bytes.
- Real Windows/Kali installations, interactive terminal behavior,
  export/PDF visual checks and live SQLite/MariaDB user-database acceptance
  still require separately documented operator field sign-off. No
  release has been published by this change.
