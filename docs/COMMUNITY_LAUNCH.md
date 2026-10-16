# PenX community launch kit

This kit helps contributors describe **PenX** accurately and promote it without making unsupported security claims. Refer to the current [README](../README.md) and [Releases](https://github.com/SLP-DEV1/PenX/releases) before publishing; capabilities can change.

## Suggested GitHub About settings

The repository's **About** fields are separate GitHub settings; committing this document does not change them.

**Description** (copy into About → Edit repository details):

> Open-source Windows-first security reconnaissance with 12 scanner options, local AI, and HTML/PDF/SARIF reports.

**Website** (optional): `https://github.com/SLP-DEV1/PenX/releases`

**Suggested topics** (GitHub supports up to 20; replace or merge based on relevance):

`cybersecurity`, `security-tools`, `penetration-testing`, `recon`, `vulnerability-assessment`, `network-scanner`, `windows`, `python`, `open-source`, `local-ai`, `ollama`, `nmap`, `nuclei`, `ffuf`, `subfinder`, `katana`, `httpx`, `nikto`, `whatweb`

Do not imply that simply enabling every scanner guarantees complete vulnerability coverage. The **12 selectable options** also include DNS, WHOIS, HTTP header and TLS checks; see [Scanner coverage](../README.md#scanner-coverage).

## Social preview

The editable artwork is [assets/penx-social-preview.svg](../assets/penx-social-preview.svg). It is **illustrated artwork, not a screenshot**. The graphic was refreshed to say **12 tools**, matching the README.

1. Export the SVG as a PNG of **1280 × 640 pixels** (2:1 aspect ratio); inspect the result for readability and clipping.
2. In GitHub, open **Settings → General → Social preview → Edit** (the location may vary with GitHub's interface).
3. Upload the exported PNG and verify the preview when sharing the repository URL.

The Social preview setting is **not** activated by adding an SVG or PNG to the repository; it requires a repository settings change. The GitHub connector may not support that administrative operation.

## Download messaging checklist

Link users to the [release page](https://github.com/SLP-DEV1/PenX/releases) instead of an assumed stable direct-download URL.

- Ask Windows users to download **PenX-Windows-x64.zip** from a release's **Assets**, not GitHub's automatically generated source code archives.
- **SHA256SUMS.txt** accompanies the ZIP; compare SHA-256 checksums after downloading.
- PenX uses a **folder-based portable build**: preserve the entire extracted directory and run `PenX.exe`.
- Third-party scanner binaries are **not included**. The first-run setup can offer consent-based installations; some tools require runtimes, administrator approval or additional manual steps.
- A local LLM is **optional** and **not included**. Ollama, LM Studio and llama.cpp API servers are supported as external local services.
- Clearly call a GitHub **Pre-release** a pre-release rather than a stable distribution.

## Community-ready short description

> PenX is an MIT-licensed, Windows-first security reconnaissance assistant built on the METATRON project. It brings 12 selectable scan and lookup options, evidence-aware local AI reviews, scan history, and HTML/PDF/JSON/SARIF reporting into one terminal workflow. Windows x64 builds are available via GitHub Releases. Scanner binaries and an LLM are not bundled, and only authorized targets should be assessed.

## Example post (for a community that allows project showcases)

**Title:** I built PenX, a Windows-first reconnaissance assistant with local AI (open source)

> I've been working on PenX, an open-source Windows-first reconnaissance tool for authorized security assessment. It combines Nmap, Nuclei, httpx, ffuf, Subfinder, Katana and other checks in one terminal interface, and can review the evidence using your own local AI server.
>
> It also supports scan history and HTML/PDF/JSON/SARIF reports. The portable Windows build is on the Releases page; scanner components are offered through consent-based setup and are not bundled.
>
> I'd love feedback about Windows installation, clarity of findings, and usability. GitHub: https://github.com/SLP-DEV1/PenX

Use this only where the community rules allow self-promotion. Do not spam identical text, purchase votes/stars, exaggerate validation or represent a synthetic demo as a real security assessment.

## Demo and reporting

Use the [documentation demo](DEMO.md) and `python scripts/generate_demo_report.py` for **synthetic** report examples. Never publish real hostnames, credentials, token values or other sensitive findings without permission. A future live demo should be recorded against an authorized local test target.

## Attributions

PenX is an independent Windows adaptation of [METATRON](https://github.com/sooryathejas/METATRON), not an official METATRON release. Refer to [LICENSE](../LICENSE) and [SECURITY.md](../SECURITY.md) for licensing and responsible reporting.
