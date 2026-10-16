# GitLab workflow for PenX

**Authoritative repository:** https://gitlab.com/SLP-DEV1/PenX

The GitLab default branch is `master`. The historical `.github/workflows/` files and links in archived refactor reports are retained as legacy audit evidence; **GitLab does not execute GitHub Actions**.

## Code and merge requests

Clone https://gitlab.com/SLP-DEV1/PenX.git and use `git pull`, `git commit` and `git push` from your existing local source checkout. Submit feature branches as GitLab merge requests. New GitLab issue and merge request templates live under `.gitlab/`.

## GitLab CI

Active jobs are configured in [`.gitlab-ci.yml`](../.gitlab-ci.yml).

- `offline-tests` runs the full offline Python regression suite and validates historical WinGet/Scoop manifests.
- `lint` runs Ruff's fatal-error rules.
- `windows-package` is **manual on regular branches** and automatic for strict version tags matching `vMAJOR.MINOR.PATCH`. It uses GitLab.com's `saas-windows-medium-amd64` Windows runner and PowerShell; no Docker image is configured for this job.
- `publish-gitlab-release` runs on version tags **only after** the Windows build succeeds. It links three artifacts uploaded into the GitLab generic package registry.

A passing Linux job does not prove the Windows executable, Inno Setup installer or first-run scanner installations will work on all Windows systems. Confirm actual Windows job logs and binaries before announcing a release.

## Publishing Windows builds

The app version and release tag must match. Do not trigger a release while tests are failing. After a verified build and with a GitLab remote configured, for example:

~~~powershell
git switch master
git pull
git tag -a v0.4.6 -m "PenX v0.4.6"
git push origin v0.4.6
~~~

**Only use that example tag if `src/penx_app/version.py` actually reports `0.4.6`, and no `v0.4.6` tag already exists.** Check `git remote -v` before pushing. Release tags trigger a Windows build, consent-based scanner setup status smoke tests, checksum generation, package uploads and creation of GitLab release links. Release assets are:

- `PenX-Setup-x64.exe` — Windows installer
- `PenX-Windows-x64.zip` — complete portable application folder
- `SHA256SUMS.txt` — SHA-256 hashes of both binaries

If any build or upload fails, no new release should be created. The installed Windows updater reads only the official GitLab Releases API; it enforces version checks, official named asset URLs, checksum verification, and explicit opt-in before installation.

No GitLab Windows release files should be advertised before a tagged pipeline has produced and published them.

## Optional GitLab issue triage

The prior GitHub issue automation is **not** natively triggered by GitLab events. The new `scripts/gitlab_issue_triage.py` adapter reuses the tested PenX reviewer and can poll one unreviewed issue per scheduled CI run. It never closes issues, never runs reported commands, and only posts one comment after validation.

To enable it in GitLab:

1. Create a project or personal access token with access to this project and the **api** scope. Store it in **Settings → CI/CD → Variables** as the *masked* `PENX_GITLAB_TRIAGE_TOKEN` variable. Never commit the token.
2. Optionally configure a *masked* `PENX_TRIAGE_GROQ_API_KEY` for source-grounded AI review. Without it, reviews are conservative and unverified; untrusted issue text may be sent to Groq when the key is enabled.
3. Create a **CI/CD pipeline schedule** in GitLab and set its variable `PENX_RUN_ISSUE_TRIAGE=1`. Use a moderate cadence, such as daily. The opt-in job is otherwise skipped.

The bot requires these GitLab project settings. A committed script **does not automatically create a schedule or provision credentials**.

## Historical distribution manifests

The `packaging/winget/` and `packaging/scoop/` draft files still contain immutable v0.4.4 GitHub asset URLs and matching published checksum values. They are **archive-only examples**, not the active GitLab release channel. Do not change those URLs without first uploading an equivalent verified binary and recalculating its hash. Scoop automatic GitHub release discovery has been disabled. Prefer source installation or actual GitLab release assets.
