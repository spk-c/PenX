# PenX v0.4.9 — release candidate notes

> **Release preparation, not publication confirmation.** This file documents the
> intended maintenance release from the current reviewed source. Download links
> and checksums must be added only after the tagged GitHub Actions build has
> actually finished successfully.

## Purpose and changes since v0.4.8

This is a cumulative maintenance release to distribute the many validated fixes
that were merged into `main` after [v0.4.8](https://github.com/spk-c/PenX/releases/tag/v0.4.8).

- Tightened NVD/OSV/GitHub advisory validation, CVE version applicability,
  CISA KEV/EPSS freshness, cache TTL and public-address research boundaries.
- Improved robust handling of native scanner output, HTTP response lifetimes,
  scan evidence trust, and bounded local file reads.
- Added Windows-safe atomic publication and consistency checks for reports,
  manifests, assessment snapshots and machine-readable JSON/SARIF exports.
- Bounded local model prompts and malformed structured responses, prevented
  duplicated source evidence annotations and strengthened redaction.
- Updated documentation and removed verified merged topic branches; project
  history, tagged versions, and optional GitLab/WinGet drafts were preserved.

## Release checks

1. `src/penx_app/version.py` and `pyproject.toml` both report **0.4.9**.
2. PR and matching immutable `main` SHA must pass full Windows/Ubuntu tests,
   Windows packaged-installer smoke, Python compatibility, CodeQL, Gitleaks
   and dependency-audit jobs.
3. `.github/workflows/publish-v0.4.9.yml` checks these results for the **same**
   main commit before creating `v0.4.9`. Because the tag is written using
   GITHUB_TOKEN, it explicitly dispatches `release.yml` *against the tag*.
4. The tagged Windows Release workflow must rerun offline tests, build the
   installer and portable ZIP, verify the EXE and installer smoke checks, and
   attach `PenX-Setup-x64.exe`, `PenX-Windows-x64.zip`,
   `SHA256SUMS.txt` and `CVE-QUALITY.json` to a verified official release.
5. Verify official GitHub release assets and SHA256 before updating the README
   download guidance or resolving [issue #80](https://github.com/spk-c/PenX/issues/80).

## Operator validation still required

**Field acceptance: NOT SIGNED OFF.** Automated checks do not prove the
operation of all twelve third-party scanners on user hardware, Npcap driver
elevation, real model endpoint compatibility, upgrades/rollbacks from existing
installations, backups restored from sanitized historical SQLite/MariaDB data,
or the visual integrity of long PDFs.

The remaining operator-owned acceptance work is tracked in
[FIELD_ACCEPTANCE.md](FIELD_ACCEPTANCE.md),
[issue #81](https://github.com/spk-c/PenX/issues/81) and
[issue #82](https://github.com/spk-c/PenX/issues/82). Use disposable or
explicitly authorized targets only; do not upload private scan logs to CI.
