# PenX — maintenance and release status

Published release rechecked: **21 October 2026**. Field-acceptance status below is not independently revalidated here; this index is not certification that PenX is defect-free or field-tested.

## Release status

- Latest published and downloadable Windows release: **[v0.4.9](https://github.com/spk-c/PenX/releases/tag/v0.4.9)** (tag: `8dec6ba14a3c082bd05058613db06ff3bf531f75`; [successful release CI](https://github.com/spk-c/PenX/actions/runs/39064672723)).
- The v0.4.9 installer and portable ZIP include the accumulated fixes merged up to the tagged release commit. Any changes merged into [main](https://github.com/spk-c/PenX/tree/main) **after** that tag require a newer published build.
- `src/penx_app/version.py` and `pyproject.toml` both identify version `0.4.9`. The versioned tag is immutable and previous `v0.4.8` binaries were not overwritten.
- Release publication: **completed** in [#80](https://github.com/spk-c/PenX/issues/80); public installer, portable ZIP, checksum file and CVE-quality artifact have been verified on GitHub. Unperformed physical Windows field acceptance remains in #81 and #82.

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
3. For a **future** release, choose a version higher than v0.4.9, update `src/penx_app/version.py` and `pyproject.toml`, and build from a newly reviewed tag; never reuse `v0.4.9`.
4. Publish the tagged Windows installer, portable ZIP and checksums via the reviewed release workflow, then update README, download instructions and pinned manifest drafts. Verify hashes independently and never move an existing release tag.

No production scanner targets, private credentials or customer databases are required for documentation/CI maintenance.
