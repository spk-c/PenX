# Distributing PenX: GitHub, WinGet, Scoop and PyPI

**Latest published release:** [PenX v0.6.1](https://github.com/spk-c/PenX/releases/tag/v0.6.1) (10 November 2026), from immutable commit `897c18811110dcef5d35eca08886c7d958afaa94`. The [release workflow](https://github.com/spk-c/PenX/actions/runs/42865524891) successfully built and verified Windows/Linux binaries, imported frozen dependency versions and checksum/SBOM/build-manifest integrity.

| Platform | File | Verified SHA-256 |
| --- | --- | --- |
| Windows installer | `PenX-Setup-x64.exe` | `a99922e88a3a3c83b12bf017b7bae3eba68c8313bd547d58087aa53c383e602a` |
| Windows portable | `PenX-Windows-x64.zip` | `5d37fbc3d50e524d8335cb9b3b8ca5c8191d4e6216fb574ba009f2454d626e44` |
| Linux Debian amd64 | `penx_0.6.1_amd64.deb` | `e5549c9fcbe46d5bcfbf8e40c18312c973512bcfcb78278af2842ba8b7c4a801` |
| Linux portable x86-64 | `PenX-Linux-x86_64.tar.gz` | `1faab42155e1dc706d2723e5e9303e3664ac850680c07388ca6d21605c6453d0` |

**Package-manager status:** Scoop and WinGet are **drafts** pinned to the released v0.6.1 ZIP and verified SHA-256; no community registry publication or unsupported upgrade promises. Independent Windows/Npcap/installer upgrades, real database recovery, visual reports and signed installer acceptance remain **NOT SIGNED OFF**.

The historical [v0.6.0 release](https://github.com/spk-c/PenX/releases/tag/v0.6.0) contains unpatched dependencies and is not the current security release. No package has been published to PyPI or npm.

## Supply-chain verification (SBOM and build manifest)

Tagged releases and manual dispatch builds publish two extra assets alongside
the archives:

- `PenX-SBOM.json` — a deterministic CycloneDX 1.5 SBOM generated from
  `requirements.lock.txt` (exact package versions and SHA-256 hashes) and
  `requirements-build.txt` (declared build-tool specifiers, which are not
  hash-locked). Byte-identical inputs produce byte-identical output; the
  document carries no serial number or timestamp.
- `PenX-BUILD-MANIFEST.json` (`penx-build-manifest-v1`) — records the exact
  commit, tag/ref, workflow event, build workflow path, Python version, and
  the size and SHA-256 of every published asset plus the SBOM's own hash.

The manifest explicitly records `"signing": {"scheme": "none"}`: no
Authenticode, sigstore, or other cryptographic signature is claimed.
Verification is SHA-256 based against the manifest.

To verify a downloaded release bundle offline, stage all published assets,
both `SHA256SUMS*.txt` files, the manifest, and the SBOM in one directory
(keeping the `linux-assets/` subfolder layout), then run:

```powershell
python release_supply_chain.py verify-release <bundle-directory>
# Optional pins:
python release_supply_chain.py verify-release <bundle-directory> --expect-version 0.6.1 --expect-commit <40-hex-commit>
```

Exit code 0 means every check passed; 1 means at least one check failed;
2 is a usage error. The verifier re-hashes every asset, enforces that each
asset, the manifest, the SBOM, and each SHA256SUMS file appear exactly once,
that each SHA256SUMS file covers exactly its platform's assets, that the
SBOM is valid CycloneDX 1.5, and that the SBOM's runtime inventory matches
`requirements.lock.txt` (override with `--lockfile`). The same commands
`sbom` and `manifest` regenerate both documents locally.

The release workflow generates and verifies the bundle before publishing;
the in-app updater is unaffected and still uses only the stable
`PenX-Setup-x64.exe` + `SHA256SUMS.txt` pair.

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
