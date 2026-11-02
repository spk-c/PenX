# PenX GitHub repository presentation

This is the reviewed public repository profile proposal for [PenX](https://github.com/spk-c/PenX), aligned to v0.6.0. The canonical machine-readable values are in [repository-profile.json](repository-profile.json). GitHub's **About / Description / Topics** settings live outside the Git tree: editing a file alone does **not** apply them.

## Description (About)

> Cross-platform security reconnaissance for Windows and Kali/Linux, with 12 scanner adapters, optional local AI, and HTML/PDF/JSON/SARIF reports.

## Website

`https://github.com/spk-c/PenX/releases/latest`

## GitHub Topics (maximum 20)

```text
cybersecurity
ffuf
httpx
kali-linux
katana
linux
local-ai
network-scanner
nikto
nmap
nuclei
penetration-testing
python
recon
sarif
security-tools
subfinder
vulnerability-assessment
whatweb
windows
```

These topics describe real project features. Do not add `exploit`, `zero-day`, `hacking-tool`, `uncensored-ai` or platform/package claims that the project cannot substantiate. Keep the topic list to 20 and avoid duplicate synonyms.

## Apply settings

Run `scripts/sync_github_repository_profile.ps1` on Windows to preview the canonical values. After signing in with `gh auth login` as an account with GitHub administration/metadata write permission, run `scripts/sync_github_repository_profile.ps1 -Apply` to update and verify Description, Website and Topics. Alternatively, use the gear icon in the repository's GitHub **About** sidebar to set them manually.

The connected GitHub connector currently does **not** expose that metadata mutation, so these values must not be described as live until the script succeeds or the GitHub About sidebar is confirmed. The script does not alter code, branches, releases, published assets or repository visibility.

## Release visibility and trust

- Keep [README.md](../README.md) focused on verified downloads, quick starts and capabilities.
- Keep [GitHub Releases](https://github.com/spk-c/PenX/releases) as the only official binary download source.
- Keep [LINUX.md](../LINUX.md), [WINDOWS.md](../WINDOWS.md), [SECURITY.md](../SECURITY.md), and [CONTRIBUTING.md](../CONTRIBUTING.md) linked and current.
- Do not claim ARM64 downloadable builds, official WinGet/Scoop/PyPI registry availability, unsigned installer authenticity, or full field certification.
- Recheck screenshots, badges, hashes, release URLs, topic accuracy and third-party licensing when releasing the next version.
