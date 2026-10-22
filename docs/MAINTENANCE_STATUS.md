# PenX — maintenance and release status

Verified on **22 October 2026**: [PenX v0.4.11](https://github.com/spk-c/PenX/releases/tag/v0.4.11) is **published**, with Windows binaries and SHA-256 digests. The tagged [Windows Release workflow](https://github.com/spk-c/PenX/actions/runs/39818462210) succeeded. Separate operator Windows/scanner/database field acceptance remains **NOT SIGNED OFF**; publication is not certification of all live environments.

## Release status

- Latest published Windows release: **[v0.4.11](https://github.com/spk-c/PenX/releases/tag/v0.4.11)**, immutable tag and release build commit `e39a8995256cfc4a7f6e5e98bb51b9e67953e552`. The version matches `src/penx_app/version.py`, `pyproject.toml`, and the Inno Setup version fallback.
- Published assets: `PenX-Setup-x64.exe`, `PenX-Windows-x64.zip`, `SHA256SUMS.txt`, `CVE-QUALITY.json`. GitHub reports SHA-256 for the ZIP `80aa869343a6dc21e1778ae0db6028a4db9f74eb5da243fac49f412d7749aa3b` and for the installer `9c1ca291f4252ab72691dfee8a581aad16c990571f6b29d7975d64c906a8c62c`. Do not confuse source-code archives with portable binaries.
- The **Scoop and WinGet draft manifests** now pin the actual v0.4.11 ZIP URL and its published SHA-256. These drafts are not yet accepted by any community repository; real native package-manager install/upgrade/rollback tests have not been independently signed off.
- Automated PR, release, smoke and post-merge checks completed successfully for the reviewed v0.4.11 chain. The [#81](https://github.com/spk-c/PenX/issues/81) and [#82](https://github.com/spk-c/PenX/issues/82) trackers were **closed** on 22 October 2026, but the separate [field acceptance checklist](FIELD_ACCEPTANCE.md) still states **NOT SIGNED OFF**. Closing issue trackers does not establish successful physical Windows/Npcap, backup-restore or human report-review tests.

## Outstanding independent acceptance

| Priority | Work item | Definition of done |
| --- | --- | --- |
| P1 | [#81 Windows/Npcap/12 scanners](https://github.com/spk-c/PenX/issues/81) | All scanner choices on an explicitly authorized disposable target; cancellation, timeouts, process tree, missing dependencies, UAC/Npcap, operator-reviewed logs |
| P1 | [#82 Database/installer/report recovery](https://github.com/spk-c/PenX/issues/82) | Restore sanitized SQLite WAL and MariaDB test copies; Windows upgrade/rollback/uninstall; long PDF/HTML/JSON/SARIF review and interrupted-publication recovery |
| P1 | [FIELD_ACCEPTANCE.md](FIELD_ACCEPTANCE.md) | Operator evidence matrix, exact test build, results, rollback and reviewer sign-off; currently **NOT SIGNED OFF** |
| P2 | Source/architecture cleanup | Inventory and prove old compatibility facades unused before removing them; widen Ruff/mypy and Windows/Python 3.13 confidence; don't delete public entrypoints without contract tests |

**Scope:** Automated CI green means only tested code contracts passed. Real scanning, model availability, security coverage, historical database backups, human PDF inspection and physical installer behavior are not proven by synthetic mocks.

## Repository hygiene

- **Main protection:** GitHub reported the `PenX protect main (PR + CI)` ruleset active on 22 October 2026; its tracked template is at [`.github/rulesets/protect-main.json`](../.github/rulesets/protect-main.json). Verify continued server-side enforcement through repository Settings → Rules. Required PR checks include Linux offline tests, Windows placeholder checks and Gitleaks; manual Windows field checks are independent.
- **CI:** Pull requests run Linux offline/test/lint checks and every push to `main` receives post-merge Linux verification. `release/*` PRs also run Windows offline regression and packaged installer smoke tests; tagged releases run the Windows release pipeline. Physical Windows/Npcap scanner and backup/recovery field acceptance remains manual and unsigned.
- **Documentation:** `docs/REFACTOR_ACCEPTANCE.md` was intentionally deleted in [#79](https://github.com/spk-c/PenX/pull/79); [FIELD_ACCEPTANCE.md](FIELD_ACCEPTANCE.md) is now the single operator field acceptance checklist. Historical refactor, audit and release notes are available through Git history, merged pull requests and tagged [GitHub Releases](https://github.com/spk-c/PenX/releases), rather than duplicated in current public documentation.
- **Branches:** The original 17 stale topic branches were removed on 22 October 2026. New temporary feature/release branches may appear while PRs are being reviewed. The [branch-prune helper](../scripts/prune_merged_github_branches.ps1) requires explicit `-Apply`, validates merged or ancestor status and live SHA, and leaves `main` untouched. GitHub's delete-ref API has no atomic SHA lease; avoid concurrent pushes during cleanup.
- **Mirrors and packaging:** Optional `.gitlab-ci.yml` and GitLab release/triage scripts are retained for the mirror. Only the current WinGet draft is kept in the working tree; older manifest snapshots remain in Git history. Do not mistake manifests for public registry availability.

## Next release checklist

1. For the **next version after v0.4.11**, update the application, packaging, installer version and reviewed release notes together; do not move the immutable `v0.4.11` tag.
2. Use a protected `release/*` PR, confirm successful Linux/Windows packaged-app, Security and applicable path-filtered package checks, then the exact `main` post-merge CI.
3. Create a **new** version tag only after the reviewed source commit is green. Publish and verify the official Windows installer, portable ZIP and SHA-256 checksums using the tagged Windows Release workflow.
4. Only **after the new assets exist**, update WinGet/Scoop draft manifests and public documentation to verified URLs and checksums. Keep Windows/Npcap, installer upgrade/rollback, database recovery and visual report field acceptance explicitly **NOT SIGNED OFF** until supported by independent operator evidence.

No production scanner targets, private credentials or customer databases are required for documentation/CI maintenance.
