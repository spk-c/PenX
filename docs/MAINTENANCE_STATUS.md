# PenX — maintenance and release status

Release preparation updated **22 October 2026**. Latest published Windows binaries: **v0.4.10**. Source version **v0.4.11** is currently a release candidate, not yet tagged or published. Windows field acceptance remains **NOT SIGNED OFF**; this index does not certify PenX as defect-free or field-tested.

## Release status

- Latest published and downloadable Windows release: **[v0.4.10](https://github.com/spk-c/PenX/releases/tag/v0.4.10)** (tag: `28227b41c43582ae0a4125440ad6675d963ff5df`; [successful Windows release CI](https://github.com/spk-c/PenX/actions/runs/39622788442)).
- The v0.4.10 installer and portable ZIP include changes through the tagged commit, including the PHP2Shell advisory. Changes merged into [main](https://github.com/spk-c/PenX/tree/main) **after** the tag require a newer build.
- `src/penx_app/version.py`, `pyproject.toml` and the installer fallback now specify **0.4.11**. This is **source preparation only**; the compiled v0.4.11 installer, portable ZIP and SHA-256 checksums do not exist until a successful tagged release workflow. Scoop/WinGet drafts remain pinned to the verified v0.4.10 ZIP, not to imaginary future assets.
- Release publication: completed for v0.4.10 via the [Windows Release workflow](https://github.com/spk-c/PenX/actions/runs/39622788442). **v0.4.11 publication is pending** the reviewed source commit, green release checks, a unique immutable tag, and a successful Windows build. Independent Windows field acceptance remains NOT SIGNED OFF; [#81](https://github.com/spk-c/PenX/issues/81) and [#82](https://github.com/spk-c/PenX/issues/82) remain open.

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
- **CI:** Pull requests always run the Linux offline/test/lint gate; every push to `main` now triggers post-merge Linux verification. Rapid successive pushes to the same branch cancel older in-progress runs to limit Actions minutes. Windows scanner and installer tests remain manual/tagged.
- **Documentation:** `docs/REFACTOR_ACCEPTANCE.md` was intentionally deleted in [#79](https://github.com/spk-c/PenX/pull/79); [FIELD_ACCEPTANCE.md](FIELD_ACCEPTANCE.md) is now the single operator field acceptance checklist. Historical refactor, audit and release notes are available through Git history, merged pull requests and tagged [GitHub Releases](https://github.com/spk-c/PenX/releases), rather than duplicated in current public documentation.
- **Branches:** The original 17 stale topic branches were removed on 22 October 2026. New temporary feature/release branches may appear while PRs are being reviewed. The [branch-prune helper](../scripts/prune_merged_github_branches.ps1) requires explicit `-Apply`, validates merged or ancestor status and live SHA, and leaves `main` untouched. GitHub's delete-ref API has no atomic SHA lease; avoid concurrent pushes during cleanup.
- **Mirrors and packaging:** Optional `.gitlab-ci.yml` and GitLab release/triage scripts are retained for the mirror. Only the current WinGet draft is kept in the working tree; older manifest snapshots remain in Git history. Do not mistake manifests for public registry availability.

## Next release checklist

1. Ensure all required Windows/Ubuntu installer, dependency and CodeQL checks pass on the exact release commit.
2. Complete the operator-owned [Windows field scenarios](FIELD_ACCEPTANCE.md) or explicitly identify any NOT RUN criteria in release notes; never claim complete field certification from CI alone.
3. For v0.4.11, verify `src/penx_app/version.py`, `pyproject.toml` and `installer/penx.iss` are aligned, and release CI passes for the exact commit. Create immutable tag `v0.4.11` once on the reviewed commit; never reuse or move an existing tag.
4. Publish Windows assets via the reviewed release workflow, then update README, download instructions and draft manifests to match verified release asset digests. Never move an existing tag.

No production scanner targets, private credentials or customer databases are required for documentation/CI maintenance.
