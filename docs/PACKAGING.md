# Distributing PenX: WinGet, Scoop and PyPI

**Status: package manifests are drafts, not public registry listings.**
PenX is a Windows-first Python application; npm is not an appropriate primary distribution channel.

The officially published [PenX v0.5.0 release](https://github.com/spk-c/PenX/releases/tag/v0.5.0) was built on **1 November 2026** by the successful [tagged Windows Release workflow](https://github.com/spk-c/PenX/actions/runs/41293851523). It contains the Windows installer `PenX-Setup-x64.exe`, portable `PenX-Windows-x64.zip`, `SHA256SUMS.txt` and `CVE-QUALITY.json`.

**v0.5.0 verified download:** Both checked-in Scoop and WinGet **draft** manifests reference the real released `v0.5.0/PenX-Windows-x64.zip` with the SHA-256 published by GitHub and in `SHA256SUMS.txt`:
`79d70936093d239698c9ec9c2a48ff696693d2b8c70cb8dd387e02ff7e34e84c`.
The official installer SHA-256 is
`74660a19d25607982e676659aa2c969739f7656375ed869f669bbe93b3047a2e`.

**Release/version warning:** A published GitHub Release is not a listing in a community package registry. The WinGet package identifier `SLP-DEV1.PenX` remains a draft identifier pending independent publisher and package-identity review. GitHub Windows and installer smoke tests are **not** proof of actual Scoop/WinGet install, upgrade or rollback, Npcap, all scanner modes, or independently reviewed recovered databases. Full field acceptance is **NOT SIGNED OFF**. Historic v0.4.11 draft manifests remain in Git history; the working tree contains only the current v0.5.0 drafts.

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
