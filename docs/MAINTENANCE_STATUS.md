# PenX — maintenance and release status

## Current release: v0.6.1 (10 November 2026)

**Published:** [PenX v0.6.1](https://github.com/spk-c/PenX/releases/tag/v0.6.1) from immutable commit [`897c1881`](https://github.com/spk-c/PenX/commit/897c18811110dcef5d35eca08886c7d958afaa94). The [authorized Windows/Linux release workflow](https://github.com/spk-c/PenX/actions/runs/42865524891) passed all Linux/Kali, Windows installer, bundled dependency, offline regression, SHA-256, SBOM and build-manifest checks before publication.

**Published assets:** Windows installer `PenX-Setup-x64.exe`, portable ZIP `PenX-Windows-x64.zip`, Debian `penx_0.6.1_amd64.deb`, Linux `PenX-Linux-x86_64.tar.gz`, two checksum files, SBOM, build manifest and CVE quality fixture. SHA-256 digests below are from the published GitHub release assets.

- **Windows ZIP SHA-256:** `5d37fbc3d50e524d8335cb9b3b8ca5c8191d4e6216fb574ba009f2454d626e44`
- **Windows installer SHA-256:** `a99922e88a3a3c83b12bf017b7bae3eba68c8313bd547d58087aa53c383e602a`
- **Linux Debian SHA-256:** `e5549c9fcbe46d5bcfbf8e40c18312c973512bcfcb78278af2842ba8b7c4a801`
- **Linux TAR.GZ SHA-256:** `1faab42155e1dc706d2723e5e9303e3664ac850680c07388ca6d21605c6453d0`

**Security:** v0.6.1 packages dnspython 2.9.2, certifi 2026.10.23 and Pillow 13.0.0 (source installs require Python 3.11–3.13). The historical [v0.6.0](https://github.com/spk-c/PenX/releases/tag/v0.6.0) downloads are **unpatched** and must not be presented as the security update.

**Package-manager status:** versioned Scoop and WinGet manifests are **drafts**, not submissions to community registries. They pin the verified v0.6.1 Windows ZIP. No signed installer is claimed: the release manifest records `signing.scheme: none`.

**Field acceptance: NOT SIGNED OFF.** Real Windows/Npcap/UAC, production upgrades/rollback, database recovery and visual report audits are still independent gates. The 36-item roadmap [#123](https://github.com/spk-c/PenX/issues/123) remains open.

**Historical:** [v0.6.0](https://github.com/spk-c/PenX/releases/tag/v0.6.0), [v0.5.0](https://github.com/spk-c/PenX/releases/tag/v0.5.0), and [v0.4.11](https://github.com/spk-c/PenX/releases/tag/v0.4.11) remain immutable. Never move existing tags.

## Outstanding independent acceptance

| Priority | Work item | Definition of done |
| --- | --- | --- |
| P1 | [#81 Windows/Npcap/12 scanners](https://github.com/spk-c/PenX/issues/81) | All scanner choices on an explicitly authorized disposable target; cancellation, timeouts, process tree, missing dependencies, UAC/Npcap, operator-reviewed logs |
| P1 | [#82 Database/installer/report recovery](https://github.com/spk-c/PenX/issues/82) | Restore sanitized SQLite WAL and MariaDB test copies; Windows upgrade/rollback/uninstall; long PDF/HTML/JSON/SARIF review and interrupted-publication recovery |
| P1 | [FIELD_ACCEPTANCE.md](FIELD_ACCEPTANCE.md) | Operator evidence matrix, exact test build, results, rollback and reviewer sign-off; currently **NOT SIGNED OFF** |
| P2 | Source/architecture cleanup | Compatibility facades inventoried via `scripts/import_inventory.py` and retired: the `llm`/`app_paths` shims were removed on 2026-10-31 and the `penx` module entrypoint is pinned public API until v1; Ruff W/B + mypy gates and the Python 3.13 compatibility matrix are in place |

**Scope:** Automated CI green means only tested code contracts passed. Real scanning, model availability, security coverage, historical database backups, human PDF inspection and physical installer behavior are not proven by synthetic mocks.

## Repository hygiene

- **Main protection:** GitHub reported the `PenX protect main (PR + CI)` ruleset active on 22 October 2026; its tracked template is at [`.github/rulesets/protect-main.json`](../.github/rulesets/protect-main.json). Verify continued server-side enforcement through repository Settings → Rules. Required PR checks include Linux offline tests, Windows checks and Gitleaks; manual Windows field checks are independent.
- **CI:** Pull requests run Linux offline/test/lint checks and every push to `main` receives post-merge Linux verification. `release/*` PRs also run Windows offline regression and packaged installer smoke tests; tagged releases run the Windows release pipeline. Physical Windows/Npcap scanner and backup/recovery field acceptance remains manual and unsigned.
- **Documentation:** `docs/REFACTOR_ACCEPTANCE.md` was intentionally deleted in [#79](https://github.com/spk-c/PenX/pull/79); [FIELD_ACCEPTANCE.md](FIELD_ACCEPTANCE.md) is now the single operator field acceptance checklist. Historical refactor, audit and release notes are available through Git history, merged pull requests and tagged [GitHub Releases](https://github.com/spk-c/PenX/releases), rather than duplicated in current public documentation.
- **Branches:** The original 17 stale topic branches were removed on 22 October 2026. New temporary feature/release branches may appear while PRs are being reviewed. The [branch-prune helper](../scripts/prune_merged_github_branches.ps1) requires explicit `-Apply`, validates merged or ancestor status and live SHA, and leaves `main` untouched. GitHub's delete-ref API has no atomic SHA lease; avoid concurrent pushes during cleanup.
- **Mirrors and packaging:** Optional `.gitlab-ci.yml` and GitLab release/triage scripts are retained for the mirror. Only the current WinGet draft is kept in the working tree; older manifest snapshots remain in Git history. Do not mistake manifests for public registry availability.

## Next release checklist

1. For the **next version after v0.6.0**, update the application, packaging, installer version and reviewed release notes together; do not move existing immutable release tags.
2. Use a protected `release/*` PR, confirm successful Linux/Windows packaged-app, Security and applicable path-filtered package checks, then the exact `main` post-merge CI.
3. Create a **new** version tag only after the reviewed source commit is green. Publish and verify Windows/Linux assets and both SHA-256 checksum files using the tagged release workflow.
4. Only **after the next version's assets exist**, update WinGet/Scoop draft manifests and public documentation to verified URLs and checksums. Keep Windows/Npcap, installer upgrade/rollback, database recovery and visual report field acceptance explicitly **NOT SIGNED OFF** until supported by independent operator evidence.

No production scanner targets, private credentials or customer databases are required for documentation/CI maintenance.
