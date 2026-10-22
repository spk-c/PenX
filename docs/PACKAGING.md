# Distributing PenX: WinGet, Scoop and PyPI

**Status: package manifests are drafts, not public registry listings.**
PenX is a Windows-first Python application; npm is not an appropriate primary distribution channel.
GitHub published [PenX v0.4.11](https://github.com/spk-c/PenX/releases/tag/v0.4.11) on **22 October 2026** with the Windows installer, portable ZIP, SHA256SUMS.txt and CVE-QUALITY.json. The [tagged Windows Release workflow](https://github.com/spk-c/PenX/actions/runs/39818462210) completed successfully. The current checked-in Scoop and WinGet **draft** manifests pin the released v0.4.11 ZIP to the SHA-256 digest reported by GitHub, but are **not** public community-registry listings. Historical WinGet drafts remain in Git history; only the latest draft is kept in the working tree.

**v0.4.11 distribution status:** Scoop and WinGet draft manifests reference the genuine released ZIP and its GitHub-reported SHA-256 digest (`80aa869343a6dc21e1778ae0db6028a4db9f74eb5da243fac49f412d7749aa3b`). The Windows release pipeline passed packaging smoke tests, **not** community-registry validation or native Scoop/WinGet install, upgrade and rollback acceptance.

## Release/version warning

Both current draft manifests reference the **published v0.4.11 ZIP** under `spk-c/PenX`, pinned to SHA-256 `80aa869343a6dc21e1778ae0db6028a4db9f74eb5da243fac49f412d7749aa3b`.
Historical draft manifests can be inspected in Git history, but must not be submitted or used as current downloads.
The WinGet package identifier `SLP-DEV1.PenX` is retained as a draft identifier; changing it or promoting this manifest to a public community repository requires separate publisher and package-identity review.
Automated GitHub Release smoke tests are **not** proof of native WinGet/Scoop install, upgrade, uninstall or rollback behavior, and full hardware/field acceptance is **NOT SIGNED OFF**.
For future versions, align tag, Python package version, executable version, official download URL and independently verified SHA-256 before updating these drafts. GitHub also reports the v0.4.11 installer SHA-256 `9c1ca291f4252ab72691dfee8a581aad16c990571f6b29d7975d64c906a8c62c` (the manifests intentionally reference the portable ZIP).

## WinGet (community repository)

1. Promote a **tested, stable** Windows release first; verify the ZIP includes `PenX/PenX.exe`.
2. Copy the three versioned manifest files under `packaging/winget/manifests/s/SLP-DEV1/PenX/<version>/`
   into a fork of [microsoft/winget-pkgs](https://github.com/microsoft/winget-pkgs), preserving the
   `manifests/s/SLP-DEV1/PenX/<version>/` directory structure.
3. On **Windows**, run `winget validate --manifest <version-manifest-directory>`, and
   `winget install --manifest <version-manifest-directory>` after enabling local manifests.
   Test `penx --version`, `penx --setup-status`, upgrades and uninstall.
4. Submit **only** those three files for one version in a community-repository PR. The package will
   become searchable with `winget install SLP-DEV1.PenX` **only after Microsoft accepts it**.
   Security scanners may flag security tools; acceptance is not guaranteed.

**Data caution:** PenX portable currently stores `.env`, `data/`, `reports/`, and downloaded
`vendor/` files beside `PenX.exe`. WinGet has no Scoop-style `persist` declaration.
**Back up those files before upgrading or uninstalling any WinGet installation.** Test upgrade
retention on Windows before treating this package as production-ready. Do not use `--purge`
unless losing those files is intended. Avoid enabling automatic unattended WinGet upgrades
until a separate user-data directory and migration strategy are tested.

## Scoop

The checked-in `packaging/scoop/penx.json` is an installable **draft** manifest.
On Windows with Scoop installed, test it directly:
```powershell
scoop install https://github.com/spk-c/PenX/raw/refs/heads/main/packaging/scoop/penx.json
penx --version
penx --setup-status
```

Publish it through a Scoop bucket after validating first install, update, and uninstall.
The manifest persists `PenX/.env`, `PenX/data`, `PenX/reports` and `PenX/vendor`
to protect user settings, scan results and downloaded scanner tools across Scoop updates.
The checked-in Scoop draft manifest has **no automatic update discovery**. For new releases, publish refreshed manifests only with verified GitHub asset URLs and checksums.

## PyPI (source distribution and wheel)

A basic Python package definition already exists at `pyproject.toml`.
The CI package-checks workflow builds both a source distribution and wheel, runs
`twine check`, installs the wheel, and exercises its CLI entry points.

Locally:
```powershell
python -m pip install --upgrade build twine
python -m build
python -m twine check dist/*
python -m pip install dist/<produced-wheel-name>.whl
penx --version
penx --setup-status
```
Do not publicly publish until the **PyPI name/ownership is confirmed**, versioning is
aligned, tests succeed on supported Windows and supported Python versions, and
the publisher configures PyPI Trusted Publishing. Uploading needs credentials and
a PyPI publisher identity; this PR deliberately does not publish a package or store tokens.
Python-only installations still require external scanners to be installed separately
with user consent. Neither local AI models nor scanner binaries are bundled.

## Maintenance checks

Run `python scripts/validate_distributions.py` after updating a manifest; it verifies
both manifests agree on version, official archive URL and pinned SHA-256.
It performs no network downloads. GitHub Actions checks offline regressions and dependency consistency,
but **cannot replace native `winget validate` and install/upgrade testing on Windows**.
