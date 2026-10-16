# PenX — Windows Installation and Troubleshooting

## Requirements

- Windows 10 or Windows 11 (64-bit recommended)
- Python **3.10 through 3.13** (3.13 recommended) for setup and source-based use
- Internet connection to download Python dependencies and the upstream scanners
- Windows Package Manager (`winget`) for automated Ruby and Strawberry Perl setup
- Administrator/UAC approval when the Nmap/Npcap driver installer requests it
- Optional: LM Studio, Ollama, or llama.cpp running a compatible local LLM API

### Installer error: `No module named 'tools'`

Current PenX versions keep internal modules such as `tools.py` under `src/`.
The Windows bootstrap runs its Python import check with that folder on
`sys.path`. A missing `tools` import in an older bootstrap does **not**
mean that the `requests` or `charset-normalizer` packages are broken.

If an earlier installer displays this error, update the **whole** PenX source
directory, preserving your `.env`, `data/` and `reports/` folders, and rerun
`install-windows.bat`. Python 3.15 may launch the bootstrap, while PenX
correctly reuses its existing Python 3.13 virtual environment; no uninstall
is necessary. The updated bootstrap only force-reinstalls HTTP packages if
their independent import check actually fails. It does not install scanners
until the Python environment check succeeds.

## Windows installer and updates (v0.4.6 and later)

The release now contains two Windows downloads:

- **`PenX-Setup-x64.exe`**: per-user installation to
  `%LOCALAPPDATA%\\Programs\\PenX`, Start menu and optional desktop shortcuts,
  and a normal uninstall entry. Installing does not require administrator
  privileges for PenX itself. Installing optional Nmap/Npcap/scanners can
  still request elevation or require `winget`.
- **`PenX-Windows-x64.zip`**: unchanged portable edition, where the
  executable, `.env`, `data/`, `vendor/`, `reports/` and related content
  can continue living together in a writable extracted directory.

For the installed edition, data is stored outside the application folder, in
`%LOCALAPPDATA%\\PenX`. Upgrading or uninstalling PenX does **not** delete
that directory, the scan history, private `.env`, downloaded scanners or
reports. Do not place personal files inside the installed application folder.

**Migrating an existing portable profile:** Exit both copies of PenX. Make a
backup of your portable directory, then copy `.env`, `data/`, `reports/`,
`evals/`, `training/`, and (optionally) `vendor/` into
`%LOCALAPPDATA%\\PenX`. Existing contents at the destination should
be backed up first and merged manually, not overwritten. The installer never
searches for or moves your portable data automatically. For MariaDB users,
preserve the external database and connection settings separately.

The installed edition performs a **read-only** GitLab stable release check at most
once every 24 hours when started. Disable the background check with
`PENX_AUTO_UPDATE_CHECK=off`. A network failure will not prevent startup.

Use `PenX.exe --check-update` to manually check or `PenX.exe --update`
to review/install updates interactively. Menu **[13] Check for Updates**
provides the same interactive flow. The updater accepts only official GitLab
PenX release asset URLs, checks the supplied SHA-256 against the
downloaded installer, then asks for confirmation before starting the
**interactive** setup. The application exits so Setup can update its files.
It never silently executes a downloaded program; the user must approve the
update first. Portable installs display the release link instead and are
not overwritten by the installed-edition updater.

The installer is not Authenticode-signed. Windows SmartScreen may warn about
an unfamiliar publisher; only download from verified official PenX release assets
and inspect the release's SHA256SUMS.txt. Hash verification detects download
corruption but is **not** a substitute for code signing.

## 1. Installation

Download or clone PenX, then run **`install-windows.bat`** in the project directory. The script creates `.venv`, installs `requirements.txt`, copies `.env.example` to `.env` when no `.env` exists, then **automatically installs all missing supported scanners**: Nmap/Npcap, Ruby/WhatWeb, Strawberry Perl/Nikto, Nuclei, ProjectDiscovery httpx, ffuf, Subfinder and Katana. No second prompt is required for the native ZIP downloads after explicitly launching the BAT. Installation does not scan any targets.

| Component | Official source / command | Installation behavior |
| --- | --- | --- |
| Nmap + Npcap | https://nmap.org/download.html | Finds the current official Windows setup from `nmap.org/dist/`, checks SHA-256 against the published digest, then opens the **interactive** installer. Keep Npcap enabled if needed for your scan types. |
| Ruby + DevKit | `winget install -e --id RubyInstallerTeam.RubyWithDevKit.3.4` | Installs the Ruby runtime required by the original WhatWeb scanner. |
| WhatWeb | https://github.com/urbanadventurer/WhatWeb | Downloads the original `v0.6.4` source. Bundler installs required gems and the setup checks `--version`. |
| Strawberry Perl | `winget install -e --id StrawberryPerl.StrawberryPerl` | Installs the Perl runtime used by Nikto. |
| Nikto | https://github.com/sullo/nikto | Downloads a reviewed, pinned upstream Git commit (not a moving `main` branch) and performs an offline Perl syntax check. |
| Nuclei | https://github.com/projectdiscovery/nuclei | Downloads and SHA256-verifies the official Windows x64 ZIP, then installs `vendor/bin/nuclei.exe`. |
| ProjectDiscovery httpx | https://github.com/projectdiscovery/httpx | Downloads and verifies the official Windows x64 ZIP, then installs `vendor/bin/httpx.exe`. |
| ffuf | https://github.com/ffuf/ffuf | Downloads and verifies the official Windows x64 ZIP, then installs `vendor/bin/ffuf.exe`. |
| Subfinder | https://github.com/projectdiscovery/subfinder | SHA256-verified Windows x64 release installed to `vendor/bin/subfinder.exe`. |
| Katana | https://github.com/projectdiscovery/katana | SHA256-verified Windows x64 release installed to `vendor/bin/katana.exe`. |

**Npcap is a Windows driver:** the Nmap installer may require interactive approval. PenX does not claim fully unattended installation. WhatWeb and Nikto source files are placed under `vendor/` and are excluded from the Git repository.

For a retry, run **`install-scanners.bat`**; it installs the same set of tools, skipping already detected binaries. If a tool cannot be downloaded or verified, the installer prints `INCOMPLETE` for that tool and the BAT reports a non-zero result. The Windows Python environment remains usable. Use **`check-windows.bat`** to see what is installed and whether the local model API can be reached. The health check **does not scan target hosts**. A missing or failed component is shown explicitly.

### First launch of a downloaded Windows release (portable EXE)

Once a verified binary is published on [GitLab Releases](https://gitlab.com/SLP-DEV1/PenX/-/releases), download `PenX-Windows-x64.zip` and extract the **entire PenX directory** into a writable location, then start `PenX.exe`.

On **the first normal EXE launch only**, PenX checks whether Nmap, Npcap, Ruby, WhatWeb, Strawberry Perl, Nikto, Nuclei, httpx, ffuf, Subfinder and Katana appear to be installed. If any are missing, it **asks before downloading or installing** the upstream tools using the same Windows installer as the source install. Internet access, `winget` and Windows administrator/UAC approval may be needed; the Nmap/Npcap installer remains interactive. Missing scanners do not prevent PenX from opening. Declining the offer is remembered so users aren't prompted on every launch.

| EXE command | Behavior |
| --- | --- |
| `PenX.exe` | First interactive launch guides local LLM setup if unconfigured, then offers missing scanner components (consent required) and opens PenX |
| `PenX.exe --setup` | Ask for consent, then install missing legacy and native scanners, even if initial offer was skipped |
| `PenX.exe --setup-native` | Ask for consent and install only Nuclei, httpx, ffuf, Subfinder and Katana |
| `PenX.exe --llm-setup` | Run the local LLM configuration wizard on demand |
| `PenX.exe --setup-status` | Show local component presence without scanning, downloading, prompting or installing |
| `PenX.exe --version` | Print version; does not run setup |
| `PenX.exe --check` | Run health checks without installing anything |

The portable folder ships **no external scanner installers or upstream scanner binaries**. The wizard retrieves scanner dependencies from their official sources on the end-user machine, and incomplete or cancelled installs can be retried. The presence check is not a substitute for `--check` and does not guarantee compatibility of third-party scanners.

If LLM settings are missing or contain the example model placeholder, the first **interactive** launch guides backend selection, URL, optional hidden API key, model selection and a short connection test. Only selected LLM keys are written to `.env`; unrelated settings are preserved. Existing configured users are not prompted, and headless/diagnostic commands do not run the wizard. Use `PenX.exe --llm-setup` or menu [13] to reconfigure (restart PenX after changing settings in the menu). The wizard does not install Ollama, LM Studio, llama.cpp, models, or GPU drivers. Install under a writable directory because SQLite data, configuration, downloaded WhatWeb/Nikto source, and the first-run marker are kept beside the EXE. You can skip scanner setup and continue with available functionality.

## 2. Fix Python 3.15 / charset_normalizer import errors

The installer prefers Python **3.13** and accepts **3.10–3.13**. If your `.venv` uses an incompatible Python version and the startup fails with an error such as:

```text
SystemError: module charset_normalizer.cd uses unknown slot ID 84
```

run **`repair-python.bat`**. It will:

1. Find a compatible Python version or attempt to install Python 3.13 using `winget`.
2. Rename the incompatible `.venv` to a backup (for example `.venv-python315-backup`).
3. Recreate `.venv`, reinstall dependencies, and verify imports.
4. Recheck scanner availability **without reinstalling Nmap, WhatWeb, or Nikto**.

Existing `.env`, scan databases, and reports are preserved. This process does not uninstall system Python. If `winget` is unavailable, install Python 3.13 from https://www.python.org/downloads/windows/ and rerun the repair script. Installation is reported as failed if dependency verification fails.

## 3. Configuration

PenX only creates `.env` from `.env.example` when the file is missing. Example for LM Studio:

```dotenv
PENX_LLM_URL=http://127.0.0.1:1234
PENX_MODEL=your-local-model
PENX_DB_ENGINE=sqlite
```

For Ollama, use `PENX_LLM_URL=http://127.0.0.1:11434` and set the model ID to one available from its local API.

### llama.cpp / llama-server on Windows

Download the Windows `llama-server.exe` from the official [llama.cpp releases](https://github.com/ggml-org/llama.cpp/releases) and point it at a chat-capable GGUF file. Example:

```powershell
llama-server.exe -m "C:\Models\model.gguf" -c 8192 --host 127.0.0.1 --port 8080 --alias penx-local
```

The server port is set **explicitly** to 8080 in this example. Match the configured port in `.env`:

```dotenv
PENX_LLM_URL=http://127.0.0.1:8080
PENX_MODEL=auto
```

`PENX_MODEL=auto` queries `GET /v1/models` before generation. It is supported only when the server advertises **exactly one** model; if several IDs are listed, set `PENX_MODEL` to the desired ID, for example `penx-local`. Without `--alias`, a llama.cpp model ID may be a GGUF filename/path. PenX also accepts URL values ending in `/v1` or `/v1/chat/completions` without duplicating paths. A protected local API can use `PENX_LLM_API_KEY=...` in your **private** `.env`.

All three backends expose the chat-completions API expected by PenX. A compatible chat template is required for useful results. If the server responds with HTTP 503, allow the GGUF model to finish loading; 401 means you may need the API key, and model-related 400/404 errors usually require checking `/v1/models`, `PENX_MODEL`, and the server's configured port. The Nmap/WhatWeb/Nikto scanner setup does **not** install llama.cpp itself.

A local LLM does not require a cloud LLM service, but optional web search and network reconnaissance communicate with outside systems.

Default paths, relative to the PenX application directory:

| Purpose | Default path |
| --- | --- |
| SQLite scan history | `data/penx.db` |
| Reports | `reports/` |
| Evaluations | `evals/` |
| Training exports | `training/` |
| WhatWeb source | `vendor/whatweb/` |
| Nikto source | `vendor/nikto/` |

If `data/metatron.db` exists and `data/penx.db` does not, PenX can continue using the previous SQLite database. **This is not a MariaDB-to-SQLite migration.** MariaDB remains optional through `PENX_DB_ENGINE=mariadb` and the additional `mysql-connector-python` dependency. Legacy `METATRON_*` settings are still recognized for compatibility. For a fresh or legacy **MariaDB** database, create/upgrade the schema in the exact order in [the MariaDB migrations guide](migrations/README.md) **before starting PenX**. The optional MariaDB backend does not create its tables automatically. Back up existing data first.

### Structured JSON reports and CVE source checks

Set `PENX_STRUCTURED_OUTPUT=auto` (default) to try schema-constrained JSON, then JSON-object output with local model servers. If unsupported, PenX explicitly warns and falls back to the legacy parser. Set `strict` to refuse invalid JSON or `off` to disable structured output.

Source checks look up public CVE IDs using NVD and CISA KEV and append references to findings. Listing a CVE **does not confirm target exploitability**. An AI quote is checked against the original scan for a match. To disable the outbound reference lookups, set `PENX_VERIFY_SOURCES=off`. For higher NVD API limits, optionally set `PENX_NVD_API_KEY` in your private `.env`. Never commit this key.

### CVE Discovery Engine

Nmap service checks now write a temporary XML file and append the completed Nmap XML to the collected evidence. PenX identifies services with a valid CPE/product version and searches NVD's CVE API for version-relevant candidates. Explicit PURLs (for example `pkg:npm/lodash@4.17.20`) are also matched against OSV and GitHub's reviewed advisories. **Arbitrary text banners are not treated as precise package identities.**

```dotenv
PENX_CVE_DISCOVERY=on
PENX_CVE_MAX_SERVICES=3
PENX_CVE_MAX_PACKAGES=4
PENX_CVE_MAX_RESULTS=15
# PENX_GITHUB_ADVISORY_TOKEN=
```

NVD response configurations with complex AND/negated environment requirements or vendor-specific versions are conservatively marked uncertain. NVD-referenced vendor advisories are included for checking patched builds, backports and distro errata, but PenX does not infer fixed status from a matching upstream version alone.

For privacy, catalogue lookups send only the observed CPE or explicit package URL/version, **not** the scanned IP address or raw scan data. Disable with `PENX_CVE_DISCOVERY=off` when fully offline operation is required. External API failures are noted in the final report.

### Prioritized CVE candidates and vendor status

PenX queries FIRST EPSS in batches for a 30-day exploitation-probability estimate, reads CVSS scores from NVD responses, and marks CISA KEV entries. Unavailable API data is explicitly reported as unknown. Scores are used to order candidate investigations, not certify target exploitability.

```dotenv
PENX_CVE_PRIORITY=on
PENX_CVE_MAX_VERIFY=20
# Only for a positively identified OS release:
# PENX_CVE_DISTRO_HINT=ubuntu:jammy
# PENX_CVE_DISTRO_HINT=rhel:9
# PENX_CVE_DISTRO_HINT=debian:bookworm
```

Ubuntu status entries are scoped to the named release and show official source-package statuses and upstream fixed-version descriptions. Red Hat reports official fix states for matching product/release entries. Debian is linked to the official tracker for manual package revision verification. PenX **does not claim the installed package is fixed** until its exact vendor package build is independently verified.

The final report also includes any new CPEs discovered in additional authorized model-requested tool scans. Their raw output is retained for subsequent source checks.

### Installed package revisions and offline accuracy tests

To compare a detected CVE against the installed vendor package, create a source package inventory on the **authorized machine**. On Debian/Ubuntu, run:

```bash
python3 export_package_inventory.py --sources openssh,openssl --output inventory.json
```

Transfer the output privately to the PenX Windows machine and configure `PENX_PACKAGE_INVENTORY=C:/PenX/inventory.json`. For Debian, download the official tracker JSON separately and optionally set `PENX_DEBIAN_TRACKER_JSON=C:/PenX/debian-tracker.json`; PenX reads this **local file** without uploading inventory details. For RHEL, manually supply a source package and its exact `epoch:version-release` from trusted RPM inventory records.

`python cve_quality.py --json` produces a machine-readable regression score against published CVE/patch version boundaries and explicitly synthetic edge cases. `python cve_quality.py --live --json` optionally checks NVD/OSV public references, without scanning a host. The results are not a real-world exploitability score.

### Qwen/llama.cpp empty answer after a successful scan

If the terminal prints `[AI STREAM]` then `Model returned empty response`, the local model may have emitted reasoning-only tokens or exhausted its `max_tokens` budget without producing final content. PenX detects this and automatically retries once without streaming. Set `PENX_LLM_RETRY_EMPTY=on` (default) and optionally `PENX_LLM_RETRY_TOKENS=16384`.

If it happens repeatedly, check the local model's thinking mode, chat template, `PENX_MAX_TOKENS`, available context, and output limits. PenX never treats the model's internal reasoning as a security finding. Incomplete analyses keep a local evidence file under `reports/recon_SL*_unanalysed.txt`, and do not save a fake assessment.

Cloudflare-proxied domains return Cloudflare edge service data during external Nmap scans. Origin software CVEs need authorized backend evidence, not proxy port banners.

### Automatic HTML/PDF after a completed scan

After the assessment has been saved, PenX writes **both** an HTML and a PDF
report into `reports/` (next to the portable EXE or source installation).
If PDF generation fails, the completed scan remains available under
**[2] View History**; select its SL# then **[1]** to regenerate both formats.
Use **[2]** there to delete only the saved HTML/PDF while keeping database
history; use **[4]** to delete the whole session and its generated reports
after two confirmations. No other files in `reports/` are removed.

## 4. Launching and scanners

**`PenX.bat`** calls `start-windows.bat`, which runs `penx.py` from the local Python virtual environment. The recon menu offers:

| Option | Action |
| --- | --- |
| `1` | Original Windows Nmap |
| `2` | Domain WHOIS lookup (Python) |
| `3` | Original Ruby WhatWeb or an **explicitly labeled, reduced-capability** Python fallback |
| `4` | HTTP header inspection (`requests`) |
| `5` | DNS lookups (`dnspython`) |
| `6` | Original Perl Nikto (no silent fallback) |
| `a` | Run all standard tools except Nikto |
| `n` | Run all tools, including slower Nikto |

The built-in Nmap scan uses `-sV -sC -T4 --open`. Arbitrary flags suggested by a language model are **not** passed through by the constrained command dispatcher. Python WHOIS focuses on domain registration data, not network ownership lookups for arbitrary IP addresses. Network permissions, Npcap, antivirus, firewall rules, and target configuration can affect scan results.

## 5. Build a Windows executable

Run **`build-exe.bat` on Windows** after installation. It installs build dependencies from `requirements-build.txt`, runs PyInstaller in `--onedir` mode, copies available upstream scanner source directories, and outputs:

```text
dist\PenX\PenX.exe
```

The script smoke-tests `PenX.exe --version` and `PenX.exe --setup-status`; neither runs a scan or downloads dependencies. **Distribute the entire `dist\PenX` folder**, not only the EXE. Python is packaged with this folder-based application, but the external Nmap/Npcap, Ruby, and Perl installations are still required for their respective scanners. On first interactive EXE launch, PenX offers the local LLM setup wizard if configuration is missing or still contains the example model placeholder. Private `.env` files and scan databases are intentionally not included.

PyInstaller is not a Windows cross-compiler. A Linux build does not create a validated Windows executable. The source repository ships build scripts, not a prebuilt EXE within the source tree. Successful tagged releases provide the portable ZIP.

### Automated Windows release builds

The legacy GitHub Actions [Windows Release workflow](.github/workflows/release.yml) triggers on pushed tags matching `v*`. It installs build dependencies, runs offline tests on a Windows runner, builds and smoke-tests `PenX.exe` (including the noninteractive scanner setup status command), packages the entire `dist/PenX` folder and publishes a ZIP plus SHA-256 checksum to the previous GitHub release channel. This workflow **does not execute on GitLab**; Windows release publishing still needs migration. The ZIP includes the consent-based first-run setup code, **not** the external scanner binaries. Manual runs provide a downloadable workflow artifact only.

The compiled folder does **not** include Nmap/Npcap, WhatWeb/Ruby, Nikto/Perl or local model files. These dependencies need separate installation on the end user's Windows machine.

## 6. Health checks and offline tests

- `check-windows.bat`: inspects Python packages, database access, scanner runtimes, and local LLM API availability without scanning outside targets.
- `run-tests.bat`: delegates to `offline_tests.py`, which discovers and runs all `tests/test_*.py` suites in separate processes. It covers isolated SQLite, export, evaluation, CLI, installer-safety, and Python-repair tests. Some checks use a local HTTP server or mocked subprocesses.
- `PenX.exe --version`: checks the version from a built executable.
- `PenX.exe --check`: runs the installed application's health check.
- `PenX.exe --setup-status`: non-scanning component presence check.
- `PenX.exe --setup`: install/retry missing scanners after explicit approval.

If Nmap setup fails, retry from the [official Nmap download page](https://nmap.org/download.html). If `winget` is missing, update Windows App Installer or obtain Ruby and Perl from their official providers. For Bundler problems, rerun `install-scanners.bat` and examine the reported gem errors.

## 7. Test coverage and known limitations

GitLab CI runs the offline regression suite on Linux. Legacy GitHub Actions also defined Windows and Ubuntu tests, but those workflows do not run on GitLab. It **does not** install Windows kernel drivers or verify live scans against external systems. The success of `winget`, Npcap/UAC dialogs, Ruby/Perl dependencies, antivirus rules, and a Windows PyInstaller build can vary by machine. Verify these components locally before relying on the tool for an assessment.

PenX is an MIT-licensed derivative of [METATRON](https://github.com/sooryathejas/METATRON); see [LICENSE](LICENSE). Third-party scanners retain their upstream licenses. **Only scan systems or networks you own or are explicitly authorized to assess.**

### Optional Windows-native Nuclei, httpx, ffuf, Subfinder and Katana

Running `install-windows.bat` or `install-scanners.bat` installs these missing tools automatically as part of explicit Windows setup. Alternatively, run `PenX.exe --setup-native` to **opt in** to installing only missing
Nuclei, ProjectDiscovery httpx, ffuf, Subfinder and Katana into `vendor/bin`. The installer
fetches the latest official upstream scanner releases and their Windows amd64 ZIPs,
requires an upstream SHA256 asset digest, verifies the entire download and
extracts only the single matching executable. Existing EXEs are not replaced.
No installer step scans a target.

These tools appear as [7] Nuclei, [8] httpx, [9] ffuf, [s] Subfinder and
[c] Katana in the New Scan selector; [d] is the built-in Python TLS check.
[a] runs standard tools 1–5, [n] adds Nikto, and [x] selects all 12 tools.
Nuclei, ffuf and Katana require explicit confirmation before any scanner starts.
Subfinder discovers subdomains passively and does not scan discoveries.
The [b] shortcut remains **Back**, not Subfinder. An optional local list can
be set with `PENX_FFUF_WORDLIST` (maximum 80 safe paths).

**Nuclei templates:** The executable alone is not sufficient for Nuclei scans.
During approved Windows setup, PenX runs the official template updater
separately. The initial community-template download can take several minutes:
the updater is now allowed **600 seconds by default** (previously 180).
For slower networks, you can raise the bounded setup timeout in PowerShell:

```powershell
$env:PENX_NUCLEI_TEMPLATE_TIMEOUT = "900"
.\\.venv\\Scripts\\python.exe penx.py --setup-native
```

A successful install must produce YAML templates in
`vendor/nuclei-templates` (or in the custom directory configured through
`PENX_NUCLEI_TEMPLATES`). If the updater times out, setup reports
`Nuclei templates: INCOMPLETE` rather than claiming success. A small
`.penx-template-update-incomplete` marker prevents partially downloaded YAML
from being treated as ready on the next run; a successful retry clears it.
Check internet, access to the relevant upstream scanner repository, VPN/proxy restrictions, then retry setup. No template updates
are performed during target scans. The installation of a scanner EXE does not
imply its templates are installed.

The ZIP distributed by PenX still does **not** contain any of these
third-party binaries. No WSL or Linux environment is required on Windows x64.


### Machine-readable offline report exports (JSON / SARIF)

Existing reviewed sessions can now be exported to **JSON** or **SARIF 2.1.0**
from the history export menu without re-running any scans or contacting an LLM.
An unattended **saved-session export** is also available:

```powershell
.\\.venv\\Scripts\\python.exe penx.py --export-session 32 --format json --redact
.\\.venv\\Scripts\\python.exe penx.py --export-session 32 --format sarif --redact
```

These commands return a nonzero exit code for an invalid/missing session or
write failure. Files are created in `reports/` with collision-resistant
names; existing files are never overwritten. Rejected hallucination entries
are excluded. Unsupported AI evidence is explicitly flagged for review and
`confirmed` is downgraded in the machine-readable output when no exact
scanner quote is found. **No raw scan log or secret configuration is exported.**
`--redact` masks the assessed target and IPv4 address literals only; other
identifiers, URLs, evidence and personal data may remain. Inspect machine
reports before sharing. This is not a fully automatic scan mode or a guarantee
of complete anonymization.
