# PenX — maintenance and release status

Published release rechecked: **21 October 2026** (v0.4.10 published; GitHub release assets verified). Field-acceptance status below is not independently revalidated here; this index is not certification that PenX is defect-free or field-tested.

## Release status

- Latest published and downloadable Windows release: **[v0.4.10](https://github.com/spk-c/PenX/releases/tag/v0.4.10)** (tag: `28227b41c43582ae0a4125440ad6675d963ff5df`; [successful Windows release CI](https://github.com/spk-c/PenX/actions/runs/39622788442)).
- The v0.4.10 installer and portable ZIP include changes through the tagged commit, including the PHP2Shell advisory. Changes merged into [main](https://github.com/spk-c/PenX/tree/main) **after** the tag require a newer build.
- `src/penx_app/version.py` and `pyproject.toml` both identify **0.4.10**, matching the published tag. GitHub confirms the installer, portable ZIP, SHA256SUMS.txt and CVE-QUALITY.json assets are uploaded; previous tags remain immutable.
- Release publication: **completed** for v0.4.10 via the reviewed [Windows Release workflow](https://github.com/spk-c/PenX/actions/runs/39622788442). Installer, portable ZIP, checksum and CVE-quality artifacts are published. Physical Windows field acceptance remains open in #81 and #82.

## Outstanding independent acceptance

| Priority | Work item | Definition of done |
| --- | --- | --- |
| P1 | [#81 Windows/Npcap/12 scanners](https://github.com/spk-c/PenX/issues/81) | All scanner choices on an explicitly authorized disposable target; cancellation, timeouts, process tree, missing dependencies, UAC/Npcap, operator-reviewed logs |
| P1 | [#82 Database/installer/report recovery](https://github.com/spk-c/PenX/issues/82) | Restore sanitized SQLite WAL and MariaDB test copies; Windows upgrade/rollback/uninstall; long PDF/HTML/JSON/SARIF review and interrupted-publication recovery |
| P1 | [FIELD_ACCEPTANCE.md](FIELD_ACCEPTANCE.md) | Operator evidence matrix, exact test build, results, rollback and reviewer sign-off; currently **NOT SIGNED OFF** |
| P2 | Source/architecture cleanup | Inventory and prove old compatibility facades unused before removing them; widen Ruff/mypy and Windows/Python 3.13 confidence; don't delete public entrypoints without contract tests |

**Scope:** Automated CI green means only tested code contracts passed. Real scanning, model availability, security coverage, historical database backups, human PDF inspection and physical installer behavior are not proven by synthetic mocks.

## Repository hygiene

- **Documentation:** `docs/REFACTOR_ACCEPTANCE.md` was intentionally deleted in [#79](https://github.com/spk-c/PenX/pull/79); [FIELD_ACCEPTANCE.md](FIELD_ACCEPTANCE.md) is now the single operator field acceptance checklist. Historical refactor, audit and release notes are available through Git history, merged pull requests and tagged [GitHub Releases](https://github.com/spk-c/PenX/releases), rather than duplicated in current public documentation.
- **Branches:** On 17 October a pre-cleanup comparison found 62 topic branches with a corresponding merged PR at the *exact* branch-head SHA, and one leftover release branch without that proof. The [safe branch-prune helper](../scripts/prune_merged_github_branches.ps1) keeps a dry-run default, rechecks PR state and SHA, and refuses paginated results. Branch pruning is **manual and opt-in**; there is no active automatic branch-deletion workflow. Review the helper's dry-run output before authorizing any deletion with GitHub CLI; **never force-delete the unverified release branch**.
- **Mirrors and packaging:** Optional `.gitlab-ci.yml` and GitLab release/triage scripts are retained for the mirror. Only the current WinGet draft is kept in the working tree; older manifest snapshots remain in Git history. Do not mistake manifests for public registry availability.

## Next release checklist

1. Ensure all required Windows/Ubuntu installer, dependency and CodeQL checks pass on the exact release commit.
2. Complete the operator-owned [Windows field scenarios](FIELD_ACCEPTANCE.md) or explicitly identify any NOT RUN criteria in release notes; never claim complete field certification from CI alone.
3. For a future version higher than v0.4.10, update `src/penx_app/version.py` and `pyproject.toml`, ensure CI is green, and create a unique reviewed tag; never reuse or move an existing tag.
4. Publish Windows assets via the reviewed release workflow, then update README, download instructions and draft manifests to match verified release asset digests. Never move an existing tag.

No production scanner targets, private credentials or customer databases are required for documentation/CI maintenance.
