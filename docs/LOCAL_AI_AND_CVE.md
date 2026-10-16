# Local AI and CVE research

Configuration, authentication, source verification and CVE interpretation. Commands and file paths assume the repository root unless stated otherwise.

## 🤖 Local AI setup

PenX works with a compatible local AI endpoint. You supply the model; PenX does **not** ship or automatically train a proprietary security model.

### Option A — LM Studio

1. Install [LM Studio](https://lmstudio.ai/), download a compatible model, and start its local API server.
2. Open the `.env` file in the PenX project directory.
3. Configure the server URL and the **actual model ID** shown by LM Studio:

~~~dotenv
PENX_LLM_URL=http://127.0.0.1:1234
PENX_MODEL=your-local-model
PENX_DB_ENGINE=sqlite
~~~

### Troubleshooting: HTTP 401/403 from local LLM

If the scan completes but AI analysis returns `401 Unauthorized`, the local LLM endpoint rejected the request's credentials. This is **not** a vulnerability found on the scanned target. Check the private `.env` in your PenX installation:

```dotenv
PENX_LLM_URL=http://127.0.0.1:8080
PENX_MODEL=auto
PENX_LLM_API_KEY=
```

For llama.cpp started with `llama-server --api-key ...`, set `PENX_LLM_API_KEY` to the matching secret; leave it blank only if the server has no authentication enabled. LM Studio and other OpenAI-compatible endpoints may configure authentication differently. Do not put keys in Git commits, logs, screenshots or issue reports. Restart PenX after changing `.env`. Existing process environment variables take precedence over `.env`.

Run `python penx.py --check` (or `.venv\Scripts\python.exe penx.py --check`) to test configuration without scanning a target. PenX also checks for model-registry authorization errors **before** running scan tools, when the backend implements `/v1/models`. A registry that does not provide `/v1/models` may still work with an explicitly configured model.

If AI fails **after** reconnaissance, PenX keeps the unanalysed scanner output under `reports/recon_SL*_unanalysed.txt` and removes the incomplete DB session. These files may contain sensitive system details: store and share them carefully. They are raw evidence, **not** completed vulnerability assessments.

### Option B — Ollama

1. Install [Ollama](https://ollama.com/) and make a supported model available.
2. Ensure Ollama's local API is running.
3. Point PenX to Ollama's compatible endpoint and use the installed model ID:

~~~dotenv
PENX_LLM_URL=http://127.0.0.1:11434
PENX_MODEL=your-local-model
PENX_DB_ENGINE=sqlite
~~~

The model name above is a placeholder, **not** a downloadable model called `your-local-model`. Replace it with your own model ID. Model quality, latency, and hardware requirements depend on the model you choose.

Local inference does not require a commercial LLM API key. If you explicitly use optional external search or review workflows, those are **not** private, offline inference.

## 🔍 CVE Discovery Engine — version-aware research

PenX now performs **automated candidate discovery**, rather than only checking CVE IDs already named by a model:

1. **Nmap XML/CPE collection:** an authorized Nmap scan keeps its human-readable output and also captures structured service/product/version/CPE data. This is used for **NVD 2.0 CPE-based CVE searches**.
2. **NVD applicability assessment:** compares CPE vendor/product and version bounds. Unknown version schemes or additional platform conditions are marked as uncertain rather than labeled vulnerable.
3. **OSV + GitHub Advisories:** queries version-specific package records **only for explicit Package URLs (PURLs)** in scan evidence (such as `pkg:pypi/requests@2.31.0`). It does not guess a package ecosystem from HTTP headers or generic service banners.
4. **Vendor advisories and backports:** shows official advisory/patch links referenced by NVD where available. Distribution patches, backports and exact affected build status still need manufacturer/package-maintainer verification; PenX **does not** automatically assert a package is fixed or vulnerable.
5. **LLM review:** verified source links and bounded candidates are shown to the local model, and included in the saved assessment. Catalog results are clearly labeled *research candidates*, never confirmed findings.

Example configuration:

```dotenv
PENX_CVE_DISCOVERY=on
PENX_CVE_MAX_SERVICES=3
PENX_CVE_MAX_PACKAGES=4
PENX_CVE_MAX_RESULTS=15
# Optional; never commit secrets:
# PENX_NVD_API_KEY=
# PENX_GITHUB_ADVISORY_TOKEN=
```

All discovery happens against public catalog APIs, not by scanning unrelated hosts. **NVD receives CPE vendor/product/version, OSV receives explicit package URLs, and GitHub receives package/version.** No scan target, credentials or raw scanner text is sent by the engine. Internet access and API availability are required; offline failures are called out as unavailable, not interpreted as no vulnerabilities. Set `PENX_CVE_DISCOVERY=off` to disable it.

CPE strings can be incorrect, NVD CPE criteria can have complex platform relationships, and many Linux distributions backport fixes. These limitations require **manual verification** against vendor and distribution advisories. The engine limits API requests to avoid excessive latency and rate limiting.

### CVE prioritization and distro-specific advisory review

The discovery engine also enriches candidates with **NVD CVSS**, **FIRST EPSS** (a 30-day exploit probability), and **CISA KEV** (known exploitation in the wild). The output distinguishes unavailable lookups from low scores. These values **prioritize investigation**; they do not prove a scanned machine is vulnerable.

A more conservative NVD evaluator interprets nested AND/OR criteria and negated conditions using *unknown* when the scanner lacks a complete platform inventory. Vendor-specific version schemes remain *uncertain* instead of being compared as generic Python package versions.

For systems where you **already know the OS distribution**, set the corresponding hint to enable official advisory lookups. Example:

```dotenv
PENX_CVE_PRIORITY=on
PENX_CVE_MAX_VERIFY=20
# Set only if independently known (never inferred from an SSH banner):
# PENX_CVE_DISTRO_HINT=ubuntu:jammy
# PENX_CVE_DISTRO_HINT=debian:bookworm
# PENX_CVE_DISTRO_HINT=rhel:9
```

- Ubuntu: checks the official Ubuntu CVE API and displays matching **release/source-package statuses and fixed-version descriptions**.
- Red Hat: displays product/release-specific package fix-state records and links to the Red Hat CVE API.
- Debian: links directly to the official release-specific Debian Security Tracker for manual confirmation, because its per-CVE tracker data cannot be safely assumed from an upstream service banner.
- **A vendor's "fixed" release does not establish that your installed binary is patched.** Exact installed package revision, architecture and package manager status must be checked locally before declaring a target fixed. The engine does not make this assertion automatically.

PenX also **re-runs candidate discovery after additional model-requested tool scans**, preserving their raw output so newly observed CPEs are not lost in the summarization step. Catalogue queries never grant the model permission to scan outside its authorized target.

### Exact installed-package comparison and quality gate

An upstream Nmap version (e.g. OpenSSH `9.2p1`) **cannot establish whether a Debian, Ubuntu or RHEL security update was backported**. PenX now supports an optional **explicit local inventory** of **source package names and exact installed versions**. It never guesses these from a remote banner, and does not execute commands on assessed remote hosts.

Example `inventory.json` supplied by the system administrator:

```json
{
  "distro": "debian",
  "release": "bookworm",
  "packages": [
    {"source": "openssh", "version": "1:9.2p1-2+deb12u3"}
  ]
}
```

Copy the inventory onto the PenX host and set:

```dotenv
PENX_PACKAGE_INVENTORY=C:/PenX/inventory.json
# Debian only: optional local Debian Security Tracker JSON snapshot (large file):
# PENX_DEBIAN_TRACKER_JSON=C:/PenX/debian-tracker.json
```

The [Debian Security Tracker export](https://security-tracker.debian.org/tracker/data/json) must be obtained separately; it is not bundled. Its schema can change, so unexpected shapes are treated as unknown rather than “fixed”. On a Debian/Ubuntu host you administer, `python export_package_inventory.py --sources openssh,openssl --output inventory.json` can produce a minimal inventory without any network access. Transfer the file only through your approved security process. For RHEL, provide an exact source package identity and canonical `epoch:version-release` manually.

PenX uses Debian's package-version ordering (epochs, tildes, revisions) and a separate RPM version comparator. It reports **below published fix**, **at/above published fix**, **vendor says not affected**, or **unknown** only when a matching distro, release and source package are available. These are *package/advisory comparisons*, **not proof the running service is unaffected**: package origin, installed binary, architecture, process restarts and additional vendor conditions may still matter.

Run the version-quality regression gate:

```powershell
python offline_tests.py
python cve_quality.py --json
# Optional, internet required: publicly known CVE reference smoke check
python cve_quality.py --live --json
```

Fixtures use published fix boundaries (e.g. CVE-2024-6387 for Debian/Ubuntu), explicit negatives, and separately labeled synthetic RPM edge cases. Their precision/recall describes **these curated fixtures only**. This is not a claim about accuracy on real networks, and no vulnerable host is scanned by CI.

## 🔎 Verified CVE references and structured JSON

PenX can request **schema-constrained JSON findings** from LM Studio, Ollama and llama.cpp, then validate field types and required values before saving. It first tries a JSON Schema response format, then JSON-object mode if needed. The default mode warns and falls back to legacy text parsing if a model cannot produce valid JSON. Enable strict mode to fail instead of falling back.

CVE identifiers are checked through the official [NVD CVE API](https://nvd.nist.gov/developers/vulnerabilities) and the [CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog). Reference statuses, exact scanner-evidence matching and source URLs are added to each finding and included in exported reports. **A CVE being listed does not establish that your target uses an affected version or is exploitable.** This requires separate manual verification.

```dotenv
PENX_STRUCTURED_OUTPUT=auto
PENX_VERIFY_SOURCES=on
# Optional private NVD API key
# PENX_NVD_API_KEY=
```

- **JSON:** `auto` (default), `strict` (reject invalid JSON) or `off` (legacy text).
- **External CVE checks:** `on` (default), or `off` for offline analysis. NVD receives public CVE IDs, not your scan target or raw scan output. CISA KEV is downloaded separately.
- **Results:** If a source is offline, the status is marked `unavailable`. `PENX_CVE_MAX_VERIFY` (default 20, maximum 30) caps individual CVE checks; installed-package status still requires vendor package evidence.
