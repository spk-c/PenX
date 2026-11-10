# PenX — maintenance and release status

**Next source candidate: v0.6.1 (10 November 2026), not published.**
Security fixes and accumulated main-branch changes are being prepared in
[PR #179](https://github.com/spk-c/PenX/pull/179); **publication is pending**.
The v0.6.0 release binaries below remain historical/unpatched (dnspython
2.8.0). No new tag, bundle signature, or independent field acceptance is
claimed. See [release blocker #178](https://github.com/spk-c/PenX/issues/178).


## Current release: v0.6.0 (2 November 2026)

**Published:** [PenX v0.6.0 for Windows and Kali/Linux](https://github.com/spk-c/PenX/releases/tag/v0.6.0). Release PR [#120](https://github.com/spk-c/PenX/pull/120) was merged into `main`. The new immutable `v0.6.0` tag resolves to reviewed commit `eb22080352a4137cd4324be7f48244ad649dc8ea`. The [tagged multi-platform release workflow](https://github.com/spk-c/PenX/actions/runs/41518241245) finished with **success**.

**Downloads:** Windows installer `PenX-Setup-x64.exe`, portable `PenX-Windows-x64.zip`, Linux amd64 `penx_0.6.0_amd64.deb`, portable `PenX-Linux-x86_64.tar.gz`, `SHA256SUMS.txt`, `SHA256SUMS-Linux.txt`, `CVE-QUALITY.json`. GitHub additionally generates source archives, which are not packaged applications.

- **Windows ZIP SHA-256:** `0851e9fb77ee222ec48b229876893bd588472337b9064ad1868182ab039a14a0`.
- **Windows installer SHA-256:** `2560cdc2b0ff239f148da1508f07243af907c90fbc7516e3395c7f5bcad03f5f`.
- **Linux Debian SHA-256:** `e023a0d48f570cdf80c46b941b70d76a747574579352e95c2c57ca488179defb`.
- **Linux TAR.GZ SHA-256:** `036106a138636c93dd3284218975b56b7de06a15230015a0b4fb4bab35caa3df`.
- **Packaging manifests:** Scoop and WinGet **drafts** now reference the verified published v0.6.0 Windows ZIP. They are not distributed through the community registries.
- **Field evidence:** Eleven Kali scanner adapters were tested against controlled local fixtures. Owner-authorized passive provider checks, local AI, SQLite crash recovery, and report checks are detailed in [Linux acceptance](LINUX_ACCEPTANCE_2026-11-02.md). Independent field acceptance remains **NOT SIGNED OFF** for all environments.

**Historical releases:** [v0.5.0](https://github.com/spk-c/PenX/releases/tag/v0.5.0) (1 November 2026) and [v0.4.11](https://github.com/spk-c/PenX/releases/tag/v0.4.11) remain available. Do not move existing release tags or confuse source archives with executable downloads. Existing security issues [#81](https://github.com/spk-c/PenX/issues/81) and [#82](https://github.com/spk-c/PenX/issues/82) were closed historically but are not evidence that all manual field checks are complete.

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
