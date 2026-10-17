# PenX v0.4.9 — published release notes

**Published stable Windows release:** [PenX v0.4.9](https://github.com/spk-c/PenX/releases/tag/v0.4.9), 17 October 2026.
The immutable tag references commit `8dec6ba14a3c082bd05058613db06ff3bf531f75`.
[Windows Release run 39064672723](https://github.com/spk-c/PenX/actions/runs/39064672723)
completed successfully with a packaged installer, portable ZIP, checksums, and
synthetic CVE quality report. This verifies the automated release build only,
not real scanner/Npcap/historical-database field acceptance.

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

## Verified publication and checksums

- `src/penx_app/version.py` and `pyproject.toml` both report **0.4.9**.
- The exact release commit passed Windows/Ubuntu offline tests, Windows
  installer/package smoke, Python compatibility, dependency audit, CodeQL
  and Gitleaks; the release workflow reran the Windows build and tests.
- `.github/workflows/publish-v0.4.9.yml` checked these results before
  creating `v0.4.9`. Since tag pushes created with GITHUB_TOKEN cannot
  trigger more workflows, it explicitly dispatched `release.yml` on the tag.
- Published `PenX-Setup-x64.exe` (**28,612,875 bytes**):
  SHA-256 `ded2c715b62fae8696b9e67bf450d0427d3d71c721caaa00335798eec4cee400`.
- Published `PenX-Windows-x64.zip` (**36,452,776 bytes**):
  SHA-256 `d80db9d78940df626f532c283c5bb41c850579ba8c9345e3c202a6a1c4a9f358`.
- `SHA256SUMS.txt` and `CVE-QUALITY.json` are also attached to the
  [official v0.4.9 release](https://github.com/spk-c/PenX/releases/tag/v0.4.9).
  These SHA-256 digests come from the published GitHub asset metadata;
  consumers should independently verify the downloaded files.

Release task: [issue #80](https://github.com/spk-c/PenX/issues/80).

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
