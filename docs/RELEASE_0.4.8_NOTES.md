# PenX v0.4.8 – post-0.4.7 security and reliability fixes

**Release preparation only.** The currently published Stable Windows download is still [v0.4.7](https://github.com/spk-c/PenX/releases/tag/v0.4.7) until a separate tagged GitHub Actions build completes and publishes verified assets.

## Intended changes since v0.4.7

- Scanner input validation, strict legacy evidence contracts, source and LLM output validation, bounded subprocess behavior.
- Consistent SQLite snapshots for session reports, training exports and review packages.
- Serialize per-session report publishing/deletion and correction/evaluation/finding operations.
- Bounded, specific SQLite-BUSY retry for safe session lock acquisition, never replay commits.
- Disallow model-directed arbitrary external search by default; optional CVE-ID-only research via `PENX_ALLOW_MODEL_WEB_SEARCH=on`. The default is **off**.
- Harden malformed NVD configuration parsing and bound external page retrieval to 512 KiB of public HTTPS without redirects.
- Correct no-op MariaDB edit feedback, preserve literal `%s` inside SQLite SQL, reject malformed scanner argv and nontext evidence, serialize full-session deletion, make evaluation deletion status honest, and bound report manifest JSON reads.

## Release build and acceptance

Release workflow: `.github/workflows/release.yml`. It runs offline regressions, builds the complete PyInstaller ZIP and per-user Windows installer, verifies installer and EXE startup, and publishes `SHA256SUMS.txt` and the CVE quality fixture.

1. Merge the associated audited changes and ensure main CI is all green.
2. Validate installer upgrade/rollback in an isolated Windows VM, scanner/Npcap permissions and representative PDF/report recovery. Document results in `docs/FIELD_ACCEPTANCE.md` and `docs/REFACTOR_ACCEPTANCE.md` without falsely marking unrun checks passed.
3. Ensure `src/penx_app/version.py` and `pyproject.toml` equal `0.4.8`; require the release tag to be `v0.4.8`.
4. **Only after authorization and readiness**, push the annotated `v0.4.8` tag to the reviewed commit. The existing workflow builds assets and creates the Release; verify its hashes and user-facing downloads. Existing Scoop/Winget manifests are historic, and their checksums must be updated only after the new archive hash is available.

**Current status:** Tag and GitHub release not created by this preparation. Green CI is not proof of real Npcap, UAC, power-loss recovery or physical upgrade acceptance. Do not claim that the full refactor is field-signed-off without actual evidence.
