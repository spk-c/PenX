# PenX — maintenance and release status

Verified on **1 November 2026**: [PenX v0.5.0](https://github.com/spk-c/PenX/releases/tag/v0.5.0) is **published** with official Windows installer, portable ZIP, CVE-quality fixtures, and SHA-256 checksums. The [tagged Windows Release workflow](https://github.com/spk-c/PenX/actions/runs/41293851523) succeeded for the immutable tagged commit `42b143ec21ced57a95e24909ffe4a143f17ad932`. Independent operator field acceptance remains **NOT SIGNED OFF**; a published installer is not certification of all real environments.

## Release status

- **Latest published Windows release: [v0.5.0](https://github.com/spk-c/PenX/releases/tag/v0.5.0)** (published 1 November 2026), reviewed through [release PR #117](https://github.com/spk-c/PenX/pull/117), with Linux and Windows offline tests, packaged app and installer smoke checks, and the tagged Windows Release workflow all green.
- Source, Python packaging and Inno Setup all identify **v0.5.0**. The tag resolves to the reviewed `main` commit `42b143ec21ced57a95e24909ffe4a143f17ad932`; do not move the tag or confuse source-code archives with Windows executables.
- Published assets: `PenX-Setup-x64.exe`, `PenX-Windows-x64.zip`, `SHA256SUMS.txt`, `CVE-QUALITY.json`. The official release checksum file and GitHub asset digests agree: ZIP SHA-256 `79d70936093d239698c9ec9c2a48ff696693d2b8c70cb8dd387e02ff7e34e84c`; installer SHA-256 `74660a19d25607982e676659aa2c969739f7656375ed869f669bbe93b3047a2e`.
- The **Scoop and WinGet draft manifests** now pin the actual published v0.5.0 ZIP and SHA-256. These are still only drafts, not community-registry submissions or proof of native package-manager installation/upgrade/rollback.
- The earlier published [v0.4.11](https://github.com/spk-c/PenX/releases/tag/v0.4.11) remains available as historical release. Issues [#81](https://github.com/spk-c/PenX/issues/81) and [#82](https://github.com/spk-c/PenX/issues/82) were closed on 22 October 2026, but the separate [field acceptance checklist](FIELD_ACCEPTANCE.md) still states **NOT SIGNED OFF**.

## Outstanding independent acceptance

| Priority | Work item | Definition of done |
| --- | --- | --- |
| P1 | [#81 Windows/Npcap/12 scanners](https://github.com/spk-c/PenX/issues/81) | All scanner choices on an explicitly authorized disposable target; cancellation, timeouts, process tree, missing dependencies, UAC/Npcap, operator-reviewed logs |
| P1 | [#82 Database/installer/report recovery](https://github.com/spk-c/PenX/issues/82) | Restore sanitized SQLite WAL and MariaDB test copies; Windows upgrade/rollback/uninstall; long PDF/HTML/JSON/SARIF review and interrupted-publication recovery |
| P1 | [FIELD_ACCEPTANCE.md](FIELD_ACCEPTANCE.md) | Operator evidence matrix, exact test build, results, rollback and reviewer sign-off; currently **NOT SIGNED OFF** |
| P2 | Source/architecture cleanup | Compatibility facades inventoried via `scripts/import_inventory.py` and retired: the `llm`/`app_paths` shims were removed on 2026-10-31 and the `penx` module entrypoint is pinned public API until v1; Ruff W/B + mypy gates and the Python 3.13 compatibility matrix are in place |

**Scope:** Automated CI green means only tested code contracts passed. Real scanning, model availability, security coverage, historical database backups, human PDF inspection and physical installer behavior are not proven by synthetic mocks.

## Repository hygiene

- **Main protection:** GitHub reported the `PenX protect main (PR + CI)` ruleset active on 22 October 2026; its tracked template is at [`.github/rulesets/protect-main.json`](../.github/rulesets/protect-main.json). Verify continued server-side enforcement through repository Settings → Rules. Required PR checks include Linux offline tests, Windows placeholder checks and Gitleaks; manual Windows field checks are independent.
- **CI:** Pull requests run Linux offline/test/lint checks and every push to `main` receives post-merge Linux verification. `release/*` PRs also run Windows offline regression and packaged installer smoke tests; tagged releases run the Windows release pipeline. Physical Windows/Npcap scanner and backup/recovery field acceptance remains manual and unsigned.
- **Documentation:** `docs/REFACTOR_ACCEPTANCE.md` was intentionally deleted in [#79](https://github.com/spk-c/PenX/pull/79); [FIELD_ACCEPTANCE.md](FIELD_ACCEPTANCE.md) is now the single operator field acceptance checklist. Historical refactor, audit and release notes are available through Git history, merged pull requests and tagged [GitHub Releases](https://github.com/spk-c/PenX/releases), rather than duplicated in current public documentation.
- **Branches:** The original 17 stale topic branches were removed on 22 October 2026. New temporary feature/release branches may appear while PRs are being reviewed. The [branch-prune helper](../scripts/prune_merged_github_branches.ps1) requires explicit `-Apply`, validates merged or ancestor status and live SHA, and leaves `main` untouched. GitHub's delete-ref API has no atomic SHA lease; avoid concurrent pushes during cleanup.
- **Mirrors and packaging:** Optional `.gitlab-ci.yml` and GitLab release/triage scripts are retained for the mirror. Only the current WinGet draft is kept in the working tree; older manifest snapshots remain in Git history. Do not mistake manifests for public registry availability.

## Next release checklist

1. For the **next version after v0.5.0**, update the application, packaging, installer version and reviewed release notes together; do not move the immutable `v0.4.11` tag.
2. Use a protected `release/*` PR, confirm successful Linux/Windows packaged-app, Security and applicable path-filtered package checks, then the exact `main` post-merge CI.
3. Create a **new** version tag only after the reviewed source commit is green. Publish and verify the official Windows installer, portable ZIP and SHA-256 checksums using the tagged Windows Release workflow.
4. Only **after the next version's assets exist**, update WinGet/Scoop draft manifests and public documentation to verified URLs and checksums. Keep Windows/Npcap, installer upgrade/rollback, database recovery and visual report field acceptance explicitly **NOT SIGNED OFF** until supported by independent operator evidence.

No production scanner targets, private credentials or customer databases are required for documentation/CI maintenance.
