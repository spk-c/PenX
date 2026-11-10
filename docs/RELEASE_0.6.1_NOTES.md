# PenX v0.6.1 — security rebuild and cumulative source updates

This is a **new packaged build**, not a claim that the v0.7–v1.0 roadmap
or independent field acceptance is complete. It includes the accumulated
reviewed source changes since v0.6.0 (more than 90 main commits before this
release-preparation PR), so it is not a dependency-only patch in behavior.

## Security fixes and compatibility

- Rebuild with hash-locked **dnspython 2.9.2** (replaces the vulnerable 2.8.0),
  **certifi 2026.10.23** and **Pillow 13.0.0** from security PR #177.
- Source installs now require **Python 3.11–3.13**. Existing Python 3.10
  virtualenvs must be rebuilt using a supported interpreter; the Windows
  repair/bootstrap path preserves user data and backs up incompatible venvs.
- Packaged Windows and Linux binaries now expose a read-only release-only
  dependency inventory; CI checks imports **inside the frozen executable**
  against the locked versions rather than assuming the build venv reflects
  shipped code.

## Additional source changes since v0.6.0

- Stricter scanner result, evidence provenance and original-source retention
  checks; saved-report traceability in JSON, SARIF, HTML and PDF.
- Opt-in, fail-closed project authorization with the audited safe scanner
  dispatch subset. Unreviewed adapters and unattended/batch operations remain
  disallowed in project mode.
- Hardened SQLite backup/restore validation and optional MariaDB logical
  backup, scratch preflight and **read-only** audits. **No live or in-place
  MariaDB restore is supported or accepted.**
- Opt-in offline SBOM and exact-version OSV candidate inspection, alongside
  initial local AI provider diagnostics and synthetic evidence benchmarks.
  These do not constitute vulnerability validation or measured real-model
  performance.

The upstream roadmap [#123](https://github.com/spk-c/PenX/issues/123) remains
open. A merged source feature or green synthetic test is not field acceptance.

## Release verification

Tagged builds must pass offline/security/Linux/Kali/Windows packaged checks,
executable dependency checks, checksum verification and the offline SBOM/build
manifest verification before publication. Available assets are the Windows
installer and ZIP, Linux amd64 `.deb` and tar archive, SHA-256 files, SBOM,
build manifest and quality report. The build manifest declares
`signing.scheme: none`; **the Windows installer is not Authenticode-signed**.
A build manifest and SHA-256 file alone are not cryptographic publisher
signatures.

**The earlier v0.6.0 downloads remain historical and unpatched.** Do not
relabel, replace or retag them. Update README and download links only when a
new v0.6.1 Release with verified assets has actually been published.

## Independent field acceptance — NOT SIGNED OFF

Physical Windows/Npcap/UAC scanner matrices, on-machine installer upgrade and
rollback, report visual review, real historical-database recovery, live
MariaDB restore, additional Linux distributions and independent operator
sign-off are **NOT SIGNED OFF**. No production database, external target scan,
or undocumented approval is authorized by this release. Use PenX only against
systems you own or are explicitly authorized to assess.
