# PenX on GitHub

**Primary repository:** https://github.com/spk-c/PenX

GitHub `main` contains the full Git history imported from the GitLab `master` branch. Use `git clone https://github.com/spk-c/PenX.git`.

## Automated checks

The active GitHub Actions workflows under [`.github/workflows/`](../.github/workflows) run offline tests on Windows and Ubuntu, tag-triggered Windows release builds, and optional issue triage. The retained `.gitlab-ci.yml` and GitLab-specific scripts are for the optional GitLab mirror and are not executed by GitHub.

## Releases

The Windows release workflow builds and smoke-tests a complete portable folder and Inno Setup installer, then publishes `PenX-Setup-x64.exe`, `PenX-Windows-x64.zip`, and `SHA256SUMS.txt` when a version tag matches the source version. Manually triggered workflow builds produce artifacts but do not create a public release. Until the first tagged release completes successfully, use [source installation](../README.md#quick-start). Automatic source code archives are not Windows binaries.

## Issue triage

The [AI issue triage workflow](../.github/workflows/issue-triage.yml) can respond to newly opened issues, owner-triggered `/penx-triage` comments, manual runs and scheduled rechecks. It uses the automatic `GITHUB_TOKEN` with separate read and write job permissions. Optionally add `PENX_TRIAGE_GROQ_API_KEY` under repository Actions secrets for AI-assisted reviews. Review safety output manually; the bot must not be treated as proof of a vulnerability.

## Secondary GitLab mirror

The older [GitLab repository](https://gitlab.com/SLP-DEV1/PenX) remains available, but updates to GitHub are **not automatically pushed there**. Historical GitLab documentation, issue templates and CI files remain for possible mirror use. Do not run both release pipelines for the same version without coordinating their output.
