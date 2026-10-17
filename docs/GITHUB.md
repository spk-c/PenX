# PenX on GitHub

**Primary repository:** https://github.com/spk-c/PenX

GitHub `main` contains the full Git history imported from the GitLab `master` branch. Use `git clone https://github.com/spk-c/PenX.git`.

## Automated checks

The active GitHub Actions workflows under [`.github/workflows/`](../.github/workflows) run offline tests on Windows and Ubuntu, tag-triggered Windows release builds, and optional issue triage. The retained `.gitlab-ci.yml` and GitLab-specific scripts are for the optional GitLab mirror and are not executed by GitHub.

## Releases

The Windows release workflow builds and smoke-tests a complete portable folder and Inno Setup installer, then publishes `PenX-Setup-x64.exe`, `PenX-Windows-x64.zip`, and `SHA256SUMS.txt` when a version tag matches the source version. Manually triggered workflow builds produce artifacts but do not create a public release. The stable [v0.4.8 release](https://github.com/spk-c/PenX/releases/tag/v0.4.8) includes verified Windows downloads; later `main` commits are not automatically included in that release. Automatic source code archives are not Windows binaries.

## Issue triage

The [AI issue triage workflow](../.github/workflows/issue-triage.yml) can respond to newly opened issues, owner-triggered `/penx-triage` comments, manual runs and scheduled rechecks. It uses the automatic `GITHUB_TOKEN` with separate read and write job permissions. Optionally add `PENX_TRIAGE_GROQ_API_KEY` under repository Actions secrets for AI-assisted reviews. Review safety output manually; the bot must not be treated as proof of a vulnerability.

## Secondary GitLab mirror

The older [GitLab repository](https://gitlab.com/SLP-DEV1/PenX) remains available, but updates to GitHub are **not automatically pushed there**. Historical GitLab documentation, issue templates and CI files remain for possible mirror use. Do not run both release pipelines for the same version without coordinating their output.

## Repository settings (owner-only)

The connected GitHub app does not expose an API to edit repository descriptions, topics or branch rules. Run the reviewed [GitHub bootstrap script](../scripts/configure_github.ps1) once using your own authenticated GitHub CLI on Windows. It configures the public repository description, homepage/topics and imports the versioned [main branch ruleset](../.github/rulesets/protect-main.json). This configuration file is a template: merely committing it does **not** enforce any rules.

~~~powershell
winget install --id GitHub.cli -e
gh auth login
pwsh -File scripts/configure_github.ps1
~~~

Use Windows PowerShell 5.1 instead of `pwsh` if PowerShell 7 is not installed:

~~~powershell
powershell -ExecutionPolicy Bypass -File scripts/configure_github.ps1
~~~

The ruleset requires pull requests and the current Linux/Windows test checks before merging, blocks branch deletion and force pushes, and requires no second approver for a single-maintainer project. It does not apply until imported by the script (or via GitHub's Rulesets settings page).

To publish a future official Windows release **after the latest main checks pass**, run the same script with `-PublishRelease`. It validates the current `main` workflow results, checks that the tag matches the version in `src/penx_app/version.py`, then creates only the appropriate Git tag. The tag triggers `.github/workflows/release.yml`, which builds and publishes the release **only on successful tests and packaging**. Do not manually upload unverified binaries or create a release with just GitHub's source code archive.

Issue triage retries one old issue per day and continues to respond to newly opened issues and manual owner re-reviews. Groq AI reviews require the separately configured `PENX_TRIAGE_GROQ_API_KEY` secret; without it, triage remains conservative.

## Current release and future publication

The stable [v0.4.8 release](https://github.com/spk-c/PenX/releases/tag/v0.4.8) has completed its tagged Windows build. For **future** versions, the owner can use `scripts/configure_github.ps1 -PublishRelease` after required checks pass. The release workflow publishes matching Windows binaries and checksums; manual Windows/Npcap/database field acceptance remains separate.

## Cleaning up merged work branches

GitHub may retain topic branches after the associated PR has been merged.
This is **not** a code or security failure. The repository includes a
conservative GitHub CLI helper, which always previews before deletion:

~~~powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\prune_merged_github_branches.ps1
~~~

If you have reviewed the candidates and want to delete them:

~~~powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\prune_merged_github_branches.ps1 -Apply
~~~

Only matching merged-PR `fix/`, `refactor/`, `release/`, `maintenance/`,
`docs/` or `quality/` heads with an unchanged commit SHA and **no open PR**
qualify. The script never deletes
`main`, never deletes unrecognized branch prefixes, and rejects any
branch changed or reopened between preview and deletion. Deletion is
irreversible through this helper; the merged pull request remains visible.
