# PenX community launch kit

Check the [README](../README.md) and [GitHub Releases](https://github.com/spk-c/PenX/releases) before sharing download links. As of October 16, 2026 **no Windows binaries have yet been published on the new GitHub repository**.

## GitHub project details

**Description:** Open-source Windows-first security reconnaissance with 12 scanner options, local AI, and HTML/PDF/SARIF reports.

**Repository:** https://github.com/spk-c/PenX

**Suggested topics:** `cybersecurity`, `security-tools`, `penetration-testing`, `recon`, `vulnerability-assessment`, `network-scanner`, `windows`, `python`, `open-source`, `local-ai`, `nmap`, `nuclei`, `ffuf`, `subfinder`, `katana`, `httpx`.

These settings must be configured in GitHub; committing this document does not change project metadata.

## Social preview

The artwork at [assets/penx-social-preview.svg](../assets/penx-social-preview.svg) is an illustration, not a live scan. Export it to 1280 × 640 PNG for sharing posts. Committing artwork does not configure GitHub link previews.

## Download guidance

Until tested Windows assets are released, point users to the [source installation](../README.md#quick-start). After release, verify **PenX-Setup-x64.exe**, **PenX-Windows-x64.zip**, and **SHA256SUMS.txt** are attached to the same official release. Source archives are not executable Windows builds.

- Preserve the complete portable application folder; it is not a single EXE.
- External scanners and optional local AI models are not bundled.
- Scanner installation is consent-based.
- Verify checksums and sanitize any published reports.

## Example community post

> PenX is an MIT-licensed, Windows-first security reconnaissance assistant for authorized targets. It combines Nmap, Nuclei, httpx, ffuf, Subfinder, Katana and other checks, local-AI-assisted evidence reviews, scan history, and HTML/PDF/JSON/SARIF reports. Source and setup: https://github.com/spk-c/PenX. Verified Windows downloads will be announced on GitHub Releases once available.

Share only where community rules allow it. Do not spam or claim synthetic demonstrations are real scans.

## Attribution

PenX is an independent Windows adaptation of [METATRON](https://github.com/sooryathejas/METATRON), not an official upstream release. See [LICENSE](../LICENSE) and [SECURITY.md](../SECURITY.md).
