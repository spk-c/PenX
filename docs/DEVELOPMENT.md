> **GitLab migration (October 2026):** Current GitLab CI is defined in `.gitlab-ci.yml` and runs Linux offline tests. The GitHub Actions sections below document legacy automation, **not active GitLab workflows**. Windows packaging and automatic release publishing are configured in GitLab CI for tested version tags, but hosted-runner execution still requires end-to-end verification. Automated GitLab issue triage has **not** been migrated from the historical GitHub workflow.

# Build and development reference

Build instructions, source layout and test commands. See also [Windows installation](../WINDOWS.md) and [Contributing](../CONTRIBUTING.md).

## 📦 Build a Windows EXE

To create a Windows executable after installing the project, run:

~~~bat
build-exe.bat
~~~

Local, CI and release builds now share the PyInstaller options in
[`scripts/build_windows.py`](../scripts/build_windows.py). Local builds
use `--clean` to discard stale caches; CI and releases use normal caching.
Inspect `python scripts/build_windows.py --help` for the options. Run the
builder on **Windows**, not Linux.

PyInstaller creates a **folder-based** application:

~~~text
dist\PenX\PenX.exe
~~~

Keep the **entire `dist\\PenX` folder** when moving the build. This is not a single-file executable. Nmap/Npcap, Ruby, Perl, WhatWeb and Nikto are **installed separately after approval at first EXE launch**, not bundled into the EXE. Prebuilt GitLab Windows ZIPs are **not yet published**; see [GitLab Releases](https://gitlab.com/SLP-DEV1/PenX/-/releases). The historical GitHub release workflow does not run in GitLab; the source tree itself does not contain a prebuilt EXE.

The executable needs to be built and checked on Windows; Linux CI does not establish that the packaged EXE works on every Windows installation.

## 📁 Project structure

~~~text
PenX/
├── penx.py                    # CLI entrypoint
├── PenX.bat                   # Windows launcher
├── install-windows.bat        # Windows setup
├── start-windows.bat          # Windows Python launcher
├── build-exe.bat              # Portable Windows executable build
├── check-windows.bat          # Non-scanning dependency check
├── offline_tests.py           # Run all suites from tests/
├── cve_quality.py             # Offline CVE quality report command
├── install_scanners_windows.py # Scanner installer command
├── src/                       # Internal application modules
│   ├── app_paths.py           # Source / EXE runtime paths
│   ├── llm.py                 # Local model analysis
│   ├── tools.py               # Recon tool integration
│   ├── db.py                  # Session management
│   └── ...                    # Other internal components
├── tests/                     # Regression tests and fixtures
│   ├── test_windows.py
│   ├── test_llm_setup.py
│   └── fixtures/
├── docs/                      # Detailed installation, dev and scanning guides
├── scripts/                   # Build, issue-triage and demo tools
│   ├── build_windows.py       # Shared PyInstaller options
│   ├── issue_triage.py        # Safe GitHub issue review and comments
│   └── feature_triage.py      # Source-grounded feature coverage checks
├── assets/                    # Repository branding
├── migrations/                # Historical database migrations
├── .env.example               # Non-secret configuration template
├── requirements.txt           # Runtime dependencies
└── .github/workflows/         # Tests and Windows releases
~~~

## ⚡ GitHub Actions build time and usage

The Windows Release workflow is intentionally run **only** for version tags
(`v*`) or when started manually. It retains all offline regression tests,
the PyInstaller build, both executable startup checks, ZIP integrity
validation, and a SHA-256 checksum.

To reduce runner minutes, network traffic and artifact storage:

- `setup-python` caches pip downloads using both runtime and build
  requirements files; installation does not upgrade pip on every run.
- PyInstaller reuses its safe analysis caches when available instead of
  explicitly clearing them with `--clean`. GitHub-hosted workers remain clean
  on a new job, and application dependencies are freshly resolved.
- Native Windows `tar.exe` builds the ZIP, then Python's `zipfile` checks
  that it contains `PenX/PenX.exe` and is readable.
- Tagged releases publish the ZIP, checksum, and quality report **once** as
  GitHub Release assets. Only manual builds also upload an Actions artifact,
  which is retained for three days.
- CI cancels superseded runs on the same branch (including duplicate push/PR
  events), distinguishes fork owners to avoid collisions, and ignores documentation-
  only changes. Feature-branch pushes run offline tests on both Windows and
  Ubuntu without a PyInstaller build; PRs and `main` still exercise the
  Windows executable build and launch checks.

Manual dispatches and tag-push releases use separate concurrency groups, so
manually previewing an existing tag cannot cancel its official release.

The release pipeline still repeats offline tests on the tagged revision;
it does **not** assume a previously successful CI run proves an arbitrary
new tag is safe. For a local clean build when troubleshooting PyInstaller,
add `--clean` manually to the local build command. Total build time
depends on runner availability, PyPI cache hits and PyInstaller dependency
discovery; no fixed speedup is guaranteed.

## 🤖 Automated GitHub issue triage

The [AI issue triage workflow](../.github/workflows/issue-triage.yml) starts on
`issues.opened`. The repository owner can rerun an existing issue by commenting
exactly `/penx-triage`, or under **Actions → AI issue triage → Run workflow**
with an issue number. The comment trigger ignores PRs and non-owner comments,
and updates existing bot comments instead of duplicating them.

**No API key is needed for basic automatic triage.** For feature proposals
the bot inspects allowlisted local production source and workflows (read-only)
and reports separately on numbered feature themes. Each receives one of
`implemented`, `partially-implemented`, `not-found-in-reviewed-code` or
`needs-verification`, with actual source-line links where available.
The bounded signature check does **not** prove a feature absent throughout the
repository. Broad review checklists are classified as `triage:audit` without
claiming a completed audit. Bug reports are assessed for duplicates and
reproduction details. Nothing is closed automatically.

**Optional free-tier AI source-code verification:** Groq supports the
`qwen/qwen3.8-27b` model through the Groq API. Create a Groq
Free account at https://console.groq.com/keys and generate an API key.
In the PenX repository, go to **Settings → Secrets and variables → Actions →
New repository secret** and save it under **`PENX_TRIAGE_GROQ_API_KEY`**.
This secret is available only to GitHub Actions; **never paste the key into
an issue, workflow file, commit, or pull request**. If a key has been pasted
into chat or published anywhere, revoke it in Groq and create a new one.

The default model is `qwen/qwen3.8-27b` in non-thinking JSON mode; optionally
override it using repository variable `PENX_TRIAGE_MODEL`. Groq's Free plan
limits apply (check https://console.groq.com/docs/rate-limits for the current
request/token quota). The workflow uses bounded allowlisted source excerpts
and up to 100 recent issues; every claimed source line/quote is verified
before granting a provisional `triage:likely-valid` label. At quota limits
(HTTP 429), expired/invalid keys, and other API failures, the issue is labeled
`triage:unverified` rather than being rejected. Without a configured API
key the existing free, rule-based triage still works.

The review job gets `contents:read` and `issues:read`, plus the optional
API secret; it cannot write to GitHub issues. A separate publish job receives
only a sanitized report and gets `issues:write`, but **not** the API secret.
It applies exactly one of `triage:likely-valid`, `triage:needs-info`,
`triage:partially-supported`, `triage:possible-duplicate`, `triage:proposal`,
`triage:audit` or `triage:unverified`, and updates the existing bot
comment if rerun. Human-managed labels remain
untouched. Neither job executes untrusted issue commands, remote scan targets,
reproduction scripts or issue-supplied URLs.

Run `python offline_tests.py` for deterministic security/behavior tests,
including `tests/test_issue_triage.py` and `tests/test_issue68_triage.py`.
The optional live AI connection still requires a real workflow run with the
configured secret; the owner-only `/penx-triage` command can refresh a review.

## 🧪 Tests and troubleshooting

Run **`python offline_tests.py`** (or **`run-tests.bat`** on Windows) for all discovered `tests/test_*.py` suites. Use `python offline_tests.py --list` to inspect the suite list. PenX includes **offline automated tests** for data management, export workflows, scanner dispatch, and Windows setup helpers. GitHub Actions runs tests on Windows and Ubuntu. They intentionally do **not** scan public targets.

| Action | Command / document |
| --- | --- |
| Check dependencies | `check-windows.bat` |
| Run local offline tests | `run-tests.bat` |
| Retry external scanner setup | `install-scanners.bat` |
| Repair Python dependencies | `repair-python.bat` |
| Build Windows executable | `build-exe.bat` |
| Installation help | [WINDOWS.md](../WINDOWS.md) |

An automated test passing does **not** prove that all third-party scanner installations, scan modes, or local AI models have been verified in every environment. PenX is actively developed; bug reports and Windows compatibility reports are welcome.
