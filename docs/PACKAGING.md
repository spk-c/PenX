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

## Optional Windows Authenticode signing and verification (P1 #190)

**Current v0.6.1 is UNSIGNED.** Its published build manifest explicitly
contains `"signing": {"scheme": "none"}`. No new signature, package release
or community registry submission is created by this verification helper.
A SHA-256 match alone is not signer authentication.

The repository includes a **read-only, Windows-only verification gate**
for a future *separately authorized, actually signed* Windows installer:

```powershell
# Both values MUST be taken from separately trusted sources, not copied
# out of the downloaded installer or an unverified GitHub issue.
$expectedSha256 = "64-lowercase-hex-from-independent-release-ledger"
$approvedSignerThumbprint = "40-hex-from-approved-signing-certificate"
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify_signed_windows_release.ps1 `
  -ArtifactPath ".\PenX-Setup-x64.exe" `
  -ExpectedSha256 $expectedSha256 `
  -ExpectedSignerThumbprint $approvedSignerThumbprint `
  -RequireTimestamp
```

The placeholders are intentionally invalid until replaced with independently
verified values. The gate hashes the EXE before and after verification,
rejects Windows reparse-point files, requires a currently trusted
Authenticode signature with the independently approved signer certificate,
optionally requires timestamp certificate presence, and rejects unexpected
byte changes. It does **not** create or trust a certificate, sign, run,
install, download, upload, or publish the artifact. The cert thumbprint is
an identifier for the operator-approved certificate, **not** a substitute
for Windows trust-chain validation. This is not an atomic file lock; use
immutable artifact storage for adversarial scenarios.

**Future controlled signing procedure (not enabled in release CI):**

1. Build the Windows installer in an isolated reviewed workflow and verify
   the build output against its originating commit and clean dependency set.
2. Obtain a code-signing certificate and timestamp service through an
   approved provider; keep private signing material in a hardware-backed
   token/HSM or equivalently protected ephemeral signing environment.
   Do not commit certificates with private keys, PFX passwords or tokens
   and never echo credentials into Actions logs or artifacts.
3. Sign **before** computing/publishing the release SHA-256 files and build
   manifest. A maintainer-approved SignTool invocation uses SHA-256 for the
   file digest and a trusted RFC3161 timestamp (`/fd SHA256 /tr <approved-url>
   /td SHA256`). Independently run `signtool verify /pa /all /v` and the
   read-only verifier above on the exact final signed EXE.
4. Only after reviewing and updating the release-manifest schema and its
   verifier should a *future* release declare the Windows EXE signed.
   ZIP/Linux assets require their own separate provenance checks; a signed
   installer does **not** sign or authenticate the whole bundle.
5. Validate signer rotation, timestamp/expiry/revocation behavior, artifact
   hashes, reproducibility, installer upgrade/rollback, and independent
   operator acceptance on disposable Windows VMs **before publishing**.

The automated Windows regression suite uses *unsigned synthetic fixtures*
to prove invalid signatures, invalid hashes and non-EXE files fail closed.
It does **not** claim a production certificate-chain positive test.
The currently gated PR dependency-review step additionally needs the GitHub
Dependency Graph prerequisite and `PENX_DEP_GRAPH_READY=true`; until those
settings are independently checked, its skipped check must remain visible
and the independent pip-audit/Gitleaks checks remain active. WinGet/Scoop
remain local drafts and require real lifecycle/data-preservation acceptance.

## Maintenance checks

Run `python scripts/validate_distributions.py` after updating a manifest; it verifies
both manifests agree on version, official archive URL and pinned SHA-256.
It performs no network downloads. GitHub Actions checks offline regressions and dependency consistency,
but **cannot replace native `winget validate` and install/upgrade testing on Windows**.
