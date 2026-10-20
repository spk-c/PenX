<p align="center">
  <img src="assets/penx-banner.png" alt="PenX — Windows security reconnaissance and local AI assessment" width="100%">
</p>

<h1 align="center">PenX</h1>

<p align="center"><strong>Windows-first security reconnaissance. Local AI. Evidence you can review.</strong></p>

<p align="center">
  PenX is an open-source terminal application that brings <strong>Nmap, Nuclei, httpx, ffuf, Subfinder, Katana</strong> and more into one security assessment workflow—with local LLM assistance and shareable reports.
</p>

<p align="center">
  <a href="https://github.com/spk-c/PenX/actions/workflows/ci.yml"><img src="https://github.com/spk-c/PenX/actions/workflows/ci.yml/badge.svg" alt="Offline CI"></a>
  <a href="https://github.com/spk-c/PenX/releases/latest"><img src="https://img.shields.io/github/v/release/spk-c/PenX?label=release" alt="Latest release"></a>
  <a href="https://github.com/spk-c/PenX/stargazers"><img src="https://img.shields.io/github/stars/spk-c/PenX?style=flat" alt="GitHub stars"></a>
  <img src="https://img.shields.io/badge/Windows-10%20%7C%2011-0078D6?logo=windows" alt="Windows 10 and 11">
  <img src="https://img.shields.io/badge/Python-3.10--3.13-3776AB?logo=python" alt="Python 3.10 to 3.13 for source installation">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-22A699" alt="MIT license"></a>
</p>

<p align="center">
  <a href="#download"><strong>Download for Windows</strong></a> ·
  <a href="#quick-start"><strong>Quick start</strong></a> ·
  <a href="docs/DEMO.md"><strong>View demo</strong></a> ·
  <a href="#documentation"><strong>Documentation</strong></a>
</p>

<p align="center">
  <a href="#why-penx">Features</a> ·
  <a href="#supported-scanners">Scanners</a> ·
  <a href="#local-ai-and-privacy">Local AI</a> ·
  <a href="#reports-and-exports">Reports</a> ·
  <a href="#safety-and-limitations">Safety</a>
</p>

> [!IMPORTANT]
> **Authorized targets only.** PenX makes real network requests. Use it only on systems you own or are explicitly permitted to assess. AI-generated findings and CVE matches are **not proof of a vulnerability**—always review the underlying evidence.
>
> **Release status:** [v0.4.9](https://github.com/spk-c/PenX/releases/tag/v0.4.9) has published Windows assets and automated release checks. Independent Windows/scanner and historical-database [field acceptance](docs/MAINTENANCE_STATUS.md) remains **not signed off**.

## Download

**The easiest way to get started is the Windows installer.** PenX v0.4.9 is available from [official GitHub Releases](https://github.com/spk-c/PenX/releases/tag/v0.4.9):

| Edition | Recommended for | Get it |
| --- | --- | --- |
| **Windows installer** (`PenX-Setup-x64.exe`) | Most Windows 10/11 users; Start menu and uninstall entry | **[Download installer](https://github.com/spk-c/PenX/releases/download/v0.4.9/PenX-Setup-x64.exe)** |
| **Portable ZIP** (`PenX-Windows-x64.zip`) | Running PenX from an extracted directory | **[Download portable ZIP](https://github.com/spk-c/PenX/releases/download/v0.4.9/PenX-Windows-x64.zip)** |
| **Source code** | Developers and Python-based installations | [Install from source](#from-source) |

**Verify your download:** Compare the file against [SHA256SUMS.txt](https://github.com/spk-c/PenX/releases/download/v0.4.9/SHA256SUMS.txt) from the same release. Extract the **complete portable ZIP**, including `_internal`; GitHub's auto-generated *Source code (ZIP)* is **not** the packaged Windows app.

> [!NOTE]
> The installer is **not Authenticode-signed** and may trigger Windows SmartScreen. Third-party scanner binaries and local AI models are **not bundled**. Read the [Windows installation guide](WINDOWS.md) before installing extra dependencies.

## Why PenX?

| Capability | What you get |
| --- | --- |
| **12 scanner adapters** | Port, service, web, DNS, subdomain and TLS reconnaissance in one terminal menu |
| **Local AI assistance** | Use your own OpenAI-compatible local LLM endpoint (LM Studio, Ollama or llama.cpp) |
| **Evidence-based review** | Scanner context, human corrections, version-aware CVE candidates and source checks |
| **Scope-aware scanning** | Passive-Only Recon, bounded active tools with consent, and separate opt-in endpoint mapping |
| **History and comparison** | Locally saved assessments, corrections and scan differences over time |
| **Report generation** | HTML/PDF reports plus saved-session JSON and SARIF 2.1.0 exports |

**PenX is a terminal/CLI application**, not a graphical dashboard or an exploitation framework. It is an independent Windows-first adaptation of the MIT-licensed [METATRON project](https://github.com/sooryathejas/METATRON).

## Quick start

### Installer or portable ZIP

1. [Download PenX](#download) and verify its checksum.
2. Run `PenX-Setup-x64.exe`, or extract the whole portable ZIP and run `PenX.exe`.
3. Follow the optional scanner setup. Some dependencies require internet access, `winget` or administrator approval (such as Npcap).
4. For AI-assisted assessments, configure a compatible local model API. No model is included; local inference is optional.
5. Choose **[1] New Scan**, enter an **authorized** IP/domain, select scan tools and review the findings.

Useful diagnostics from a portable executable folder:

~~~powershell
.\PenX.exe --setup-status  # Check setup; does not scan or download
.\PenX.exe --setup         # Interactive scanner setup
.\PenX.exe --llm-setup     # Optional local model setup
.\PenX.exe --check         # Local diagnostics
~~~

### From source

Windows source installation supports Python **3.10–3.13** (3.13 recommended):

~~~powershell
git clone https://github.com/spk-c/PenX.git
cd PenX
.\install-windows.bat
.\start-windows.bat
~~~

Setup prepares the Python environment and handles supported scanner setup with consent. Use `check-windows.bat` for diagnostics and `install-scanners.bat` to retry missing scanners. **Back up** existing `.env`, `data/` and `reports/` before updating. [Windows troubleshooting →](WINDOWS.md)

## How PenX works

~~~text
Authorized target
     │
     ▼
Choose scope and scanners
     │
     ▼
Collect scanner evidence
     │
     ├──► Optional local AI and CVE research
     │
     ▼
Human review / corrections
     │
     ▼
Saved history ──► HTML · PDF · JSON · SARIF
~~~

[![Illustrated PenX workflow](assets/penx-demo-flow.svg)](docs/DEMO.md)

*Illustration, not a live scan recording. The [demo guide](docs/DEMO.md) also shows how to generate sample reports from synthetic data without scanning a host.*

## Supported scanners

PenX provides **12 scanner adapters** and one separate **[e] endpoint-mapping workflow**. Tools with missing dependencies or failures are reported as unavailable—not silently marked successful.

| Key | Scanner | Purpose |
| :---: | --- | --- |
| `1` | **Nmap** | Ports, services, product and CPE evidence; some modes need Npcap |
| `2` | **WHOIS** | Domain registration data |
| `3` | **WhatWeb** | Web technology detection; labeled limited fallback |
| `4` | **HTTP headers** | Response and security header inspection |
| `5` | **DNS** | DNS record lookups |
| `6` | **Nikto** | Optional web-server checks |
| `7` | **Nuclei** | Bounded HTTP/TLS template checks with consent |
| `8` | **ProjectDiscovery httpx** | HTTP probing and technology information |
| `9` | **ffuf** | Bounded path discovery |
| `s` | **Subfinder** | Passive subdomain inventory; no automatic follow-up scans |
| `c` | **Katana** | Bounded same-host crawling with consent |
| `d` | **TLS check** | Certificate and TLS handshake checks, not a full cipher audit |
| `e` | **Endpoint mapping** *(separate)* | Opt-in Katana → ffuf same-origin workflow |

### Scan presets

~~~text
[0] Passive-Only Recon             External source lookups; no active probes
[a] Standard Scan                  Tools 1–5
[n] Standard Scan + Nikto          Tools 1–6
[x] Full Scan                      All 12; active checks require consent
[1–9, s, c, d, e]                  Individual selections
[Esc]                              Back
~~~

For example, enter `1 4 8 s d` to select five tools. The separate **[e] workflow is never included in Full Scan**. Passive-Only Recon may still contact external lookup services. Active tools such as Nuclei, ffuf and Katana require explicit consent before starting. Full Scan does not imply every third-party tool completed successfully.

[Scanner coverage, scope and timeout details →](docs/SCANNING_AND_REPORTS.md)

## Local AI and privacy

PenX passes collected scanner evidence to an **OpenAI-compatible model endpoint you control**. Compatible local servers may include **LM Studio, Ollama or llama.cpp**. Local inference needs no paid cloud AI service, but you must provide and run your own model.

- **Human review is essential.** AI conclusions and remediation suggestions can be wrong; compare them with scanner evidence and authoritative sources.
- **CVE research is candidate discovery.** NVD/CPE lookups, package advisories and version applicability can guide investigation, but are not verified host vulnerabilities.
- **Local AI is not the same as offline scanning.** Setup downloads dependencies, scanners contact authorized targets, and optional WHOIS, RDAP, NVD, certificate-transparency and web-search providers use external services.
- **Protect sensitive data.** Local SQLite history, optional MariaDB storage and generated reports can include identifiers, endpoints and secrets. Never commit real `.env` files, API keys or scan logs.
- **Export redaction is limited.** Review any output before publication.

[Configure local AI and CVE research →](docs/LOCAL_AI_AND_CVE.md)

## Reports and exports

After a **successfully committed assessment**, PenX generates HTML and PDF reports in `reports/`. Use **[2] View History** to inspect/correct findings, regenerate reports, compare assessments and manage sessions.

Export a saved session to JSON or **SARIF 2.1.0** without rescanning or re-prompting the LLM (source installation):

~~~powershell
.\.venv\Scripts\python.exe penx.py --export-session 32 --format json --redact
.\.venv\Scripts\python.exe penx.py --export-session 32 --format sarif --redact
~~~

Replace `32` with an actual session ID. `--redact` only masks selected fields, **not all sensitive data**.

To generate example HTML/PDF reports with **synthetic data only**, without scanning a target or contacting an LLM:

~~~powershell
python scripts/generate_demo_report.py
~~~

[Demo and sample reports →](docs/DEMO.md)

## Safety and limitations

> [!CAUTION]
> PenX is intended for **authorized defensive research**. It is not an exploitation framework, a vulnerability guarantee or a substitute for manual assessment. Validate all findings independently.

Third-party runtimes, privileges and networks affect scanner availability. Automated tests and release packaging do **not** establish complete real-world Windows/Npcap/database acceptance; see the [maintenance status](docs/MAINTENANCE_STATUS.md). WinGet and Scoop manifests in this repository are **unpublished drafts**, not proof of public package-registry availability; see [packaging](docs/PACKAGING.md).

## Documentation

| Guide | Contents |
| --- | --- |
| [Windows setup](WINDOWS.md) | Installer, portable edition, dependencies, updates and troubleshooting |
| [Scanning and reports](docs/SCANNING_AND_REPORTS.md) | Scanner behavior, scope rules, evidence, history and exports |
| [Local AI and CVE research](docs/LOCAL_AI_AND_CVE.md) | Endpoint configuration, keys and candidate verification |
| [Demo](docs/DEMO.md) | Illustrated workflow and synthetic reports |
| [Development](docs/DEVELOPMENT.md) | Architecture, tests, CI and Windows builds |
| [Maintenance status](docs/MAINTENANCE_STATUS.md) | Published release and pending field acceptance |
| [Packaging](docs/PACKAGING.md) | GitHub assets and draft distribution manifests |
| [Contributing](CONTRIBUTING.md) | Code contributions and offline test guidance |
| [Security policy](SECURITY.md) | Authorized use and responsible disclosure |

## Contributing

Issues and pull requests are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) and run `python offline_tests.py` before submitting changes. Remove keys, private target details and personal data from logs or screenshots. Report sensitive PenX vulnerabilities through [SECURITY.md](SECURITY.md), not in a public issue.

## License and attribution

PenX uses the [MIT License](LICENSE) and is an **independent Windows-first adaptation** of [METATRON by Soorya Thejas](https://github.com/sooryathejas/METATRON), not an official upstream release. Third-party scanners retain their own licenses.

<p align="center">
  <strong>Find PenX useful?</strong> <a href="https://github.com/spk-c/PenX/stargazers">Star it</a> ·
  <a href="https://github.com/spk-c/PenX/releases">Releases</a> ·
  <a href="https://github.com/spk-c/PenX/issues">Report an issue</a>
</p>
