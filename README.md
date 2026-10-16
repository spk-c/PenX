<p align="center">
  <img src="assets/penx-banner.png" alt="PenX — Windows-first AI security reconnaissance assistant" width="100%">
</p>

<h1 align="center">PenX</h1>

<p align="center"><strong>Windows-first security reconnaissance with local AI and human-reviewed findings.</strong></p>

<p align="center">One terminal for authorized scans, evidence-based reviews, and locally saved HTML, PDF, JSON, and SARIF reports.</p>

<p align="center">
  <a href="https://github.com/spk-c/PenX/actions/workflows/ci.yml"><img alt="Offline tests" src="https://github.com/spk-c/PenX/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/spk-c/PenX/releases"><img alt="GitHub releases" src="https://img.shields.io/badge/Releases-GitHub-181717?logo=github"></a>
  <a href="https://github.com/spk-c/PenX/stargazers"><img alt="GitHub stars" src="https://img.shields.io/github/stars/spk-c/PenX?style=social"></a>
  <img alt="Windows 10 and 11" src="https://img.shields.io/badge/Windows-10%20%2F%2011-0078D6?logo=windows">
  <img alt="Python 3.10–3.13" src="https://img.shields.io/badge/Python-3.10--3.13-3776AB?logo=python">
  <a href="LICENSE"><img alt="MIT license" src="https://img.shields.io/badge/license-MIT-22A699"></a>
</p>

> [!NOTE]
> **GitHub home:** This project is maintained at [spk-c/PenX](https://github.com/spk-c/PenX). The new GitHub repository does not yet have published Windows binaries. Install from source until a verified Windows installer and portable ZIP are attached under [GitHub Releases](https://github.com/spk-c/PenX/releases). GitHub source archives are not ready-to-run Windows applications.

<p align="center">
  <a href="#quick-start"><strong>Install from source</strong></a> ·
  <a href="https://github.com/spk-c/PenX/releases"><strong>GitHub Releases (binaries pending)</strong></a> ·
  <a href="docs/DEMO.md"><strong>View demo</strong></a> ·
  <a href="WINDOWS.md"><strong>Installation help</strong></a>
</p>

<p align="center">
  <a href="#quick-start">Quick start</a> ·
  <a href="#scanner-coverage">Scanners</a> ·
  <a href="#scan-presets">Scan presets</a> ·
  <a href="#local-ai-and-privacy">Local AI &amp; privacy</a> ·
  <a href="#reports-and-exports">Reports</a> ·
  <a href="#documentation">Documentation</a>
</p>

> [!IMPORTANT]
> **Authorized targets only.** PenX makes real network requests. Use it only on systems you own or are explicitly permitted to assess. AI-generated vulnerability findings are **not verified proof**; review scanner evidence independently.

## Quick start

### Windows source installation (available now)

Clone the maintained GitLab repository and run the consent-based Windows setup:

~~~powershell
git clone https://github.com/spk-c/PenX.git
cd PenX
.\install-windows.bat
.\start-windows.bat
~~~

Python **3.13 is recommended** (source support: 3.10–3.13). The setup configures a virtual environment and Python dependencies, and may offer third-party scanner installation **with your consent**. Internet access, `winget`, and administrator approval may be needed. Run `check-windows.bat` for diagnostics or `install-scanners.bat` to retry missing scanners. Preserve private `.env`, `data/`, and `reports/` files when updating.

### Windows installer and portable ZIP (pending GitHub release)

The intended release assets are **`PenX-Setup-x64.exe`** (installer), **`PenX-Windows-x64.zip`** (portable application folder), and **`SHA256SUMS.txt`** (integrity check). Verify they are actually attached to a published, tested [GitHub Release](https://github.com/spk-c/PenX/releases) before using the binary installation instructions in [WINDOWS.md](WINDOWS.md). **No Windows release binaries are currently published on GitHub.** Do not use GitHub's automatic source archive as an EXE.

When a portable ZIP becomes available, extract the **entire folder** (including `_internal`) and run `PenX.exe`. Scanner binaries and local AI models are not bundled. The in-app updater now checks **stable, verified GitHub releases**. It only offers a Windows installer when both the official release asset and its checksum exist, and never installs without explicit consent.

**Useful commands for a verified Windows binary (once available):**

~~~powershell
.\PenX.exe --setup-status   # Checks only, no downloads or scans
.\PenX.exe --setup          # Consent-based scanner setup
.\PenX.exe --llm-setup      # Optional local LLM setup
.\PenX.exe --check          # Local diagnostics
~~~

**WinGet and Scoop manifests are historical drafts**, not evidence that PenX is available in a public package registry; see [distribution documentation](docs/PACKAGING.md).

## What is PenX?

**PenX** is an open-source, Windows-first security assessment assistant built on the MIT-licensed [METATRON](https://github.com/sooryathejas/METATRON) project. It unifies scanner output, evidence-aware local-AI assistance, history, review corrections, and reporting in one terminal application.

- **One CLI workflow:** select tools, review results, compare assessments, and manage reports.
- **Local-first AI:** connect an OpenAI-compatible local LLM API; no paid cloud AI service is required for local inference.
- **Evidence-based decisions:** structured findings, reviewer corrections, CPE/CVE candidate lookups, NVD/CISA checks, and scan comparisons.
- **Local storage:** SQLite by default, optional MariaDB integration.
- **Ready-to-share output:** automatic HTML/PDF for successfully saved assessments, plus saved-session JSON and SARIF exports.
- **Windows delivery:** batch setup, folder-based PyInstaller releases, and offline CI tests.

**Limits:** A CVE catalogue match does not prove host exploitability. PenX is not an exploitation framework, a complete vulnerability guarantee, or a substitute for manual assessment.

## Scanner coverage

There are **12 selectable scanner tools**. Missing runtimes, permission errors, or unavailable endpoints are reported rather than silently treated as successful scans.

| Key | Scanner | Purpose | Implementation |
|:---:|---|---|---|
| <code>1</code> | **Nmap** | Ports, services and CPE evidence | Native Nmap; some modes require Npcap |
| <code>2</code> | **WHOIS** | Domain registration | Python integration |
| <code>3</code> | **WhatWeb** | Web technology fingerprinting | Ruby tool; clearly labeled limited fallback |
| <code>4</code> | **HTTP headers** | Response/security headers | Python requests |
| <code>5</code> | **DNS** | DNS record lookup | Python dnspython |
| <code>6</code> | **Nikto** | Web-server checks | Perl/Nikto, optional |
| <code>7</code> | **Nuclei** | Bounded HTTP/TLS template checks | Explicit active-scan consent |
| <code>8</code> | **ProjectDiscovery httpx** | HTTP probing/technology information | Native Go-based scanner |
| <code>9</code> | **ffuf** | Bounded path discovery | Limited wordlist/rate/time |
| <code>s</code> | **Subfinder** | Passive subdomain inventory | No automatic follow-up scanning |
| <code>c</code> | **Katana** | Bounded same-host crawling | Explicit active-scan consent |
| <code>d</code> | **TLS check** | Verified handshake, certificate expiry | Python standard library; not a full cipher audit |

Scanner setup on Windows x64 can install **Nuclei, httpx, ffuf, Subfinder and Katana** from official, SHA-256-verified releases with consent. Other tools have their own upstream dependencies and licenses. PenX does **not** scan newly discovered subdomains automatically.

### Scan presets

~~~text
[0] Passive-Only Recon                 (external source lookups; no active probes)
[a] Standard Scan                      (tools 1–5)
[n] Standard Scan + Nikto              (tools 1–6)
[x] Full Scan                          (all 12; active checks require consent)
[1–9, s, c, d] Individual choices
[Esc] Back
~~~

For example, enter <code>1 4 8 s d</code> to select five tools. <code>b</code> and <code>back</code> remain navigation aliases; **Subfinder is <code>s</code>**. Nuclei, ffuf and Katana require consent before **any selected tool** begins. Full Scan runs the selected adapters sequentially; it is not a scheduled background scan or evidence of successful completion by every tool.

Read [Scanning and reports](docs/SCANNING_AND_REPORTS.md) for scope rules, timeouts, active versus passive scanning, and interpretation of findings.

## Local AI and privacy

PenX can pass scanner evidence to a **locally hosted, OpenAI-compatible model API**. Supply your own endpoint, model name and optional authentication key in the local setup wizard or private <code>.env</code>. A compatible running model is needed for AI-assisted assessments.

- **Local-first is not fully offline.** Installation downloads dependencies; scanners contact authorized targets; optional WHOIS, RDAP, certificate transparency, Shodan, NVD, CVE and web-search providers contact external services.
- **Human review matters.** AI can produce unsupported findings, false positives, or incorrect remediation. PenX records evidence and corrections to support review, not replace it.
- **Keep results private.** History and reports can contain addresses, endpoints, and potentially sensitive evidence. Never commit real <code>.env</code> files, model API keys, or target scan logs.
- **Redaction is limited.** Export redaction does not remove every identifier or personal datum.

See [Local AI and CVE research](docs/LOCAL_AI_AND_CVE.md) for model setup, authenticated endpoints, source validation and optional local NVD caching.

## Reports and exports

After a successfully committed assessment, PenX generates HTML and PDF reports in <code>reports/</code>. Use **[2] View History** to inspect or edit findings, regenerate reports, delete exported files without deleting history, or remove a session with confirmation.

Saved sessions can also be exported to **JSON** or **SARIF 2.1.0** without re-running scanners or sending another LLM prompt:

~~~powershell
.\.venv\Scripts\python.exe penx.py --export-session 32 --format json --redact
.\.venv\Scripts\python.exe penx.py --export-session 32 --format sarif --redact
~~~

Replace <code>32</code> with an existing session ID. <code>--redact</code> masks selected addresses and target fields, **not all sensitive data**. Review exports before publishing.

## Demo

[![Illustrated PenX workflow](assets/penx-demo-flow.svg)](docs/DEMO.md)

*Illustration, not a live scan recording.* Generate synthetic HTML/PDF sample reports using PenX exporters **without scanning hosts or calling an LLM**:

~~~powershell
python scripts/generate_demo_report.py
~~~

See the [offline demo walkthrough](docs/DEMO.md). For an up-to-date feature overview, use the README and the [GitHub Releases page](https://github.com/spk-c/PenX/releases) (after binaries are published), not an illustration as proof of a live scan.

## Repository layout

~~~text
PenX/
├── penx.py                 # Terminal entry point
├── src/                    # Scanners, local AI, storage, reporting
├── tests/                  # Offline regression suites
├── docs/                   # Detailed user/developer guides
├── assets/                 # Branding and illustrations
├── install-windows.bat     # Windows setup
├── install-scanners.bat    # Retry missing scanners
├── start-windows.bat       # CLI launcher
├── run-tests.bat           # Offline tests
├── build-exe.bat           # Folder-based EXE build
├── .env.example            # Configuration template (no secrets)
├── .gitlab-ci.yml          # Optional GitLab mirror pipeline
└── .github/workflows/      # Active GitHub tests, releases and issue triage
~~~

Tagged GitHub Windows releases should publish **PenX-Setup-x64.exe** (installer), **PenX-Windows-x64.zip** (portable), and **SHA256SUMS.txt** after Windows build/test verification. These files are **not yet available** on GitHub. The ZIP contains the Python application and first-run setup assistant, **not** the proprietary model or third-party scanner EXEs.

## Documentation

| Guide | Covers |
|---|---|
| [Windows setup](WINDOWS.md) | Source and EXE installation, repair, diagnostics |
| [Scanning and reports](docs/SCANNING_AND_REPORTS.md) | Scanner behavior, scope, evidence, history and exports |
| [Local AI and CVEs](docs/LOCAL_AI_AND_CVE.md) | Local endpoints, keys, NVD/CVE verification |
| [Demo](docs/DEMO.md) | Illustrated flow and synthetic reports |
| [Community launch kit](docs/COMMUNITY_LAUNCH.md) | Sharing guidance, repository metadata and social-preview setup |
| [Development](docs/DEVELOPMENT.md) | Architecture, offline tests, CI and Windows builds |
| [GitHub workflow](docs/GITHUB.md) | GitHub Actions, releases and issue triage |
| [GitLab mirror](docs/GITLAB.md) | Optional GitLab workflow and mirror setup |
| [Contributing](CONTRIBUTING.md) | Pull requests and development guidelines |
| [Security policy](SECURITY.md) | Responsible vulnerability disclosure |

## Contributing

Issues and pull requests are welcome for Windows support, scanner integration, testing, docs, and reproducible bugs. Run <code>python offline_tests.py</code> before submitting a pull request. Remove secrets, private-target details, and personally identifying content from logs and screenshots. Read [CONTRIBUTING.md](CONTRIBUTING.md) and use the [issue tracker](https://github.com/spk-c/PenX/issues).

To report a security issue in PenX itself, follow [SECURITY.md](SECURITY.md) instead of public disclosure. If you find the project useful, consider [starring it](https://github.com/spk-c/PenX/stargazers). See the [community launch kit](docs/COMMUNITY_LAUNCH.md) for accurate sharing examples.

## License and attribution

PenX is released under the **MIT License** ([LICENSE](LICENSE)) and builds on [METATRON by Soorya Thejas](https://github.com/sooryathejas/METATRON). It is an **independent Windows adaptation**, not an official upstream METATRON release. Nmap, Npcap, WhatWeb, Nikto, Nuclei, httpx, ffuf, Subfinder, Katana and other dependencies retain their own licenses.
