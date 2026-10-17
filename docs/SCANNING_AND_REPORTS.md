# Scanning, review and reports

Detailed walkthrough of PenX reconnaissance, passive sources, assessment output, scan comparisons and locally stored data.

## 🚀 Usage

### 1. Start a scan

Launch PenX and choose **`[1] New Scan`**. Enter a domain or IP address that you own or are expressly authorized to assess.

~~~text
[1] New Scan
  [Esc]  Back to main menu

[?] Enter target IP or domain: 192.0.2.10
~~~

Press **Esc** at the target prompt to return directly to the main menu
**without pressing Enter**. You can still type **`0`**, **`b`** or **`back`**
and confirm with Enter. Select Passive-Only Recon **after** entering the target, in the tool picker. If you cancel
before selecting scanners, no scan, local-AI request, or history session is created.

The example address belongs to a documentation-only range; substitute an authorized, reachable target for real testing.

Web checks preserve explicit ports in targets such as `example.test:8443`,
`[2001:db8::1]:8443`, and `https://example.test:8443/`. Use brackets to specify
an IPv6 port. Invalid or empty ports are rejected instead of falling back to
80/443. HTTP failure headings and unavailable DNS responses do not count as
usable scan evidence; at least one selected source must return evidence before
AI assessment starts.

**Scope guard:** IP/CIDR input is accepted only for networks containing at most **256 addresses** (IPv4 `/24` or smaller, IPv6 `/120` or smaller). Invalid CIDR prefixes, numeric pseudo-domains, and broader networks are rejected rather than converted into a different scan target. Split a larger authorized network into smaller subnets. The Nmap timeout defaults to 180 seconds and may be configured with `PENX_NMAP_TIMEOUT` (clamped to 30–900 seconds). Model-requested `-Pn` is rejected because the fixed scanner adapter does not implement it.

### 2. Choose your scanners

~~~text
[0] Passive-Only Recon (no active scans)
[1] Nmap
[2] WHOIS
[3] Web fingerprint (WhatWeb)
[4] HTTP headers
[5] DNS
[6] Nikto
[7] Nuclei
[8] ProjectDiscovery httpx
[9] ffuf
[s] Subfinder (passive)
[c] Katana (same-host crawl)
[e] Endpoint Mapping (opt-in Katana + targeted ffuf)
[d] TLS certificate / handshake
[a] Standard Scan (1–5)
[n] Standard Scan + Nikto (1–6)
[x] Full Scan (all 12; active-check confirmation)
[Esc] Back to main menu
~~~

At the tool-selection menu, pressing **Esc** immediately cancels *before any
scanner starts* and returns to the main menu. The same key works in History,
Scan Diff, Risk Review and Export selection; Edit/Delete also retains
**`[12] Back`**. In **Select Tools**, `0` starts exclusive **Passive-Only Recon**, not Back. Use **Esc**, `b`, or `back` to return; other menus still accept `0` for Back.

Esc key detection uses the native Windows console key reader (no WSL needed).
On interactive Linux/macOS terminals PenX uses terminal key input. For
redirected input and consoles that do not expose an interactive terminal,
the typed aliases still work. Once a scanner has started running, Esc does
not forcibly terminate it; this is **menu navigation only**.

Select individual tools or a group. Some operations can take longer, especially a Nikto-inclusive scan.

### 3. Review the AI analysis

PenX collects scanner output and can pass the evidence to a local language model. Its analysis workflow can propose potential security findings, suggested remediation, and further supported checks.

**Always review the underlying scanner evidence before calling a finding verified.**

### 4. Use history, corrections, and reports

The HTML and PDF exporters follow the actual PenX CLI identity: a near-black
terminal background, large **magenta PENX** masthead, green `[+]` and `[01]`
section labels, monospaced metadata, and severity-colored finding panels.
HTML adapts the card grid to screen width and provides a white print stylesheet.
The PDF uses the same dark aesthetic with a repeated magenta PENX header,
neon-green headings, risk badge, footer, and page numbers; findings flow across
A4 pages without the former cramped multi-column table.

All displayed metrics come from the **saved session**, never placeholder dashboard
numbers. Findings remain **separate from recommendations**; original model text is
explicitly marked unverified. The HTML report includes no remote fonts or scripts.
Existing reports can be restyled via **View History → [1] Regenerate**.

Each report starts with an executive overview and grouped severity counts,
followed by findings, recommendations, mitigations, attempted exploitation and
review corrections. The **original AI transcript is explicitly unverified**:
collapsed by default in HTML and moved to the last PDF appendix. It is still
available for auditing; it is never presented as an automatically verified
finding. HTML has no external scripts, images or fonts and supports printing.

Reports generated before this update retain their old appearance until you
select **View History → [1] Export / regenerate HTML and PDF** for the
corresponding session. The underlying saved assessment and evidence are not
altered by restyling.

Choose **`[2] View History`** and enter a scan SL# to inspect saved
results. Completed scans automatically export HTML and PDF into `reports/`
immediately after their database transaction commits; these filenames include
the session ID and sanitized target. Exports happen **before** the on-screen
finding/risk display. A PDF/HTML error warns the user but does not roll back
valid scan history. Failed or pending assessments cannot generate a completed
report.

The session's **History / Reports** submenu supports:
- **[1] Export/regenerate both HTML + PDF** from the current saved records.
- **[2] Delete exported HTML/PDF only.** The database, findings and history
  are retained, so the reports can be regenerated on demand.
- **[3] Edit session findings** using the existing edit/delete workflow.
- **[4] Delete the entire saved scan AND its HTML/PDF files.** Two separate
  confirmations are required for this irreversible action.

Deletion is scoped to the **exact two file paths** for the selected SL# and
target. Symlinks are refused, and unrelated report files (including other
sessions, trend exports and raw recon backups) are never removed. The scan
database remains authoritative: manually edited findings require explicitly
regenerating the reports to reflect the new corrections.

Additional main-menu options support external evaluation packages, importing review results, JSONL exports of corrected sessions, and separately distilled analysis rules. These are review and data-management features; PenX does not automatically fine-tune a model when you correct a finding.

### Scan comparison, trend history, and regression alerts

From the main menu choose **[9] Scan Diff & Trends**, enter an existing target,
then compare any two saved sessions of that exact target. PenX reports:

- New/persistent/not-observed vulnerabilities and severity changes.
- Newly opened or no-longer-observed ports, and service/version changes, **only**
  when both Nmap scans have completion evidence.
- A chronological summary of saved risk levels and finding counts.
- A JSON, HTML, and PDF comparison report written locally to the ignored reports directory.
- Separate Shodan InternetDB index changes for matching public IPs; these never count as live Nmap observations.
- An **optional** local-model prose summary of the deterministic diff.

For CIDR or multi-host scans, ports are compared by host address, protocol, and
port number. Reordering hosts does not create a service change. Comparisons
without unambiguous host addresses (including multi-host text-only results)
are marked inconclusive instead of merging different hosts' services.

Each newly saved scan of a previously assessed target also prints a regression
comparison against the previous session. This is an **on-scan check**, not a
scheduler. PenX does not initiate periodic scans. **Not observed** does not mean
**fixed**: filters, errors and missing scanner coverage can explain differences.

### Passive-Only Recon + Shodan InternetDB

Choose **[1] New Scan**, enter the target, then choose **[0] Passive-Only Recon** in Select Tools. PenX queries *third-party* DNS resolvers,
registry WHOIS, Certificate Transparency (crt.sh) and RDAP.

**Shodan InternetDB is enabled by default with no API key:** it enriches public
IPv4 addresses with externally indexed ports, CPEs, hostnames, tags, and
potential CVE matches. For a domain, PenX resolves its public DNS A records
and looks up at most three unique public IPv4 addresses (configurable 1–5).
Private/reserved addresses and IPv6 are skipped. A domain using shared hosting,
a proxy or CDN can resolve to an IP serving **other** sites; the IP index is not
proof of what the requested domain itself exposes.

An optional **Shodan Host API** integration offers deeper service and product
information for accounts with the required Shodan membership/API permissions.
When a key is configured PenX also checks Shodan account plan/credit status.
Authorization errors (401/403), insufficient access (402), missing data (404)
and rate limits (429) are reported without exposing keys or retrying endlessly.
Optional Censys lookups remain available for public IP addresses.

Private configuration in the project-local `.env` file:

~~~dotenv
PENX_SHODAN_INTERNETDB=on
PENX_SHODAN_MAX_IPS=3
# PENX_SHODAN_API_KEY=your-private-shodan-key
# PENX_CENSYS_API_ID=
# PENX_CENSYS_API_SECRET=
~~~

Set `PENX_SHODAN_INTERNETDB=off` to turn off free InternetDB lookups.
Shodan premium lookups are still possible if a private key is set.
The API key and secret are never written to the report.

**Limitations and licensing:** InternetDB is a periodically refreshed external
IP index, **not a live scan**. Shodan says its free InternetDB service is
offered for *non-commercial use*, including use within a company, but not for
building paid commercial products. Check the [official terms](https://blog.shodan.io/introducing-the-internetdb-api/)
before distributing InternetDB functionality in a commercial offering.
Some InternetDB CVEs are unverified. Treat them as **research candidates**;
independent target/version and vendor-advisory evidence is required before
claiming a confirmed vulnerability or remediation.

**Scan Diff & Trends** compares separately stored InternetDB observations
across sessions, **only for IPs found in both snapshots**. It labels ports as
"newly indexed"/"no longer indexed" and CVEs as newly listed/no longer listed.
These are **not** Nmap port changes or confirmed fixes.

Passive mode does **not** contact the assessed target via HTTP, TLS or a
scanner, and blocks model-requested TOOL/SEARCH dispatch. DNS registries and
external providers **do receive the domain/IP being looked up**, so this is
not an anonymity mode. Missing or rate-limited lookups are not evidence of
absence. Only investigate targets you are authorized to assess.

### Risk scores and candidate MITRE ATT&CK technique mapping

Choose **[11] Risk + MITRE ATT&CK Review** for a saved session. PenX calculates
an explainable 0–100 **internal prioritization score** from recorded severity
and finding confidence. It does not pretend to know missing CVSS, EPSS, CISA
KEV membership or real external exposure. A small, documented set of
behavior-oriented text indicators may suggest candidate ATT&CK techniques;
a CVE by itself is **not** evidence of a particular ATT&CK technique.

Override the score, ATT&CK IDs or quick-win/planned classification interactively.
These human overrides are kept privately under
`data/risk_overrides.json` and included when exporting the per-session
`reports/risk_SL<id>.json` file. Reopen the view to check applied changes.

### Live scanner and model output

A streamed model answer must end with a successful completion signal. If the
connection ends before that signal, the partial answer is rejected and follows
the existing bounded non-streaming retry path. Tokens already shown live are
not proof that an assessment completed.

Choose **[12] Terminal Output** to toggle between **QUIET** and **LIVE** for
the current session. LIVE streams subprocess lines and compatible local LLM
SSE tokens as they arrive. Nmap receives progress flags in live mode.
The equivalent startup setting is `PENX_LIVE_OUTPUT=1` in your private .env
or process environment. The default remains QUIET for compatibility.
Percentage completion is not fabricated: scanners that do not emit progress
will show text only. The final saved scan report is identical in either mode.

**Windows without WSL remains supported.** No Docker / Lab Mode / Offline
Replay or nonstandard UI dependency was added.

### How the workflow fits together

~~~text
  Authorized IP / domain
           |
           v
    Reconnaissance
 Nmap / WHOIS / WhatWeb
  HTTP / DNS / Nikto
           |
           v
   Evidence collection
           |
           v
   Local LLM analysis
   + optional tool loop
           |
           v
 Review / verify / correct
           |
           v
    Local scan history
     SQLite / MariaDB
           |
           v
  HTML / PDF / JSONL
~~~

### Local Qwen returns an empty response

If Nmap completes successfully but analysis says `Model returned no assistant answer`, the issue is the **local model response**, not a scanner failure. Reasoning-heavy models such as Qwen may use the completion budget without returning final `content`, particularly in SSE streaming mode.

PenX now detects this condition, reports the server's `finish_reason` and whether reasoning output was seen, and automatically retries **once without streaming**. The retry appends Qwen's `/no_think` instruction and uses a larger output budget. Raw reasoning is **never** treated as an AI finding or executed as a scanner command.

```dotenv
PENX_LLM_RETRY_EMPTY=on
PENX_LLM_RETRY_TOKENS=16384
# If still exhausted (and your model context supports it):
PENX_MAX_TOKENS=16384
```

If the retry also fails, check your Qwen server's chat template, model context/output budget and reasoning settings. PenX keeps the previously collected reconnaissance evidence as an unanalysed local file instead of recording a fake assessment. This does not prove the host has any vulnerability.

**Cloudflare note:** a scan of a Cloudflare-proxied domain normally observes the **Cloudflare edge** (for instance 80/443/8080/8443), not the actual WordPress/PHP backend. Do not assign origin-host CVEs based on these proxy banners. Obtain origin software/package versions only through an authorized backend inventory or trusted local data.

## 🗄️ Data and privacy

Legacy SQLite databases retain their stored values when missing fields are
added. Reports, evaluations, and training exports read columns in a fixed order
regardless of the database's original layout.

- **SQLite is the default**. No separate database server is needed for a basic installation.
- An existing **MariaDB** server can be configured through `.env` if preferred.
- Scan sessions, reports, corrections, and learned review rules are stored on the machine running PenX by default.
- Scanners connect to the systems being assessed. Optional web search and manually exported external evaluation packages may disclose the information you send.
- Treat `.env`, database files, scan output, exports, and model-evaluation packages as potentially sensitive. Do not commit them to a public repository.

See [`.env.example`](../.env.example) for supported configuration variables and [`.gitignore`](../.gitignore) for excluded local artifacts.


## Large scans, progress and local evidence privacy

PenX limits the **initial scanner text sent to the local model** to
`PENX_SCAN_INPUT_MAX_CHARS=60000` characters by default (configurable from
2,048 to 500,000). The trimmed model input explicitly reports that some lines
were omitted. The unmodified raw scan is still retained for CVE matching,
coverage checks and the user's reports; a truncated prompt must not be treated
as proof that unmentioned services or vulnerabilities do not exist.

For visible scanner output set `PENX_LIVE_OUTPUT=1` in `.env` and restart
PenX. Active scanners then stream output as it arrives; press **Ctrl+C** to
interrupt the operation. Scanner subprocesses already run with
`shell=False` and have per-scanner deadlines. PenX is still a terminal
application, not a full nonblocking job dashboard.

Nmap stores temporary XML inside `tempfile.TemporaryDirectory`, which
removes that temporary directory at normal completion. Stored scan history,
auto-generated reports and failed-scan recovery files are **persistent**
rather than temporary. They may contain sensitive banners, IPs or headers:
limit Windows account access, keep them out of synchronized/public folders,
and remove them through PenX's history/report controls when no longer needed.
Deleting a file is **not** guaranteed secure erasure on SSDs.

### Authorized endpoint mapping with Katana + ffuf

Select **[e] Endpoint Mapping** explicitly and confirm the active HTTP checks.
This mode does **not** run automatically with [x] Full Scan or from the LLM.

1. Katana crawls only the precise authorized HTTP(S) scheme, hostname and port,
   at depth 1 and a **24-page cap**. Redirect following is disabled. The crawler
   runs with one worker, a native rate cap of 2 requests/s, and a short deadline.
2. Parsed Katana JSONL feeds a local inventory, deduplicated by URL path.
   Each entry retains **parameter names**, observed HTTP methods and source
   scanner labels, but **not query values, request bodies, cookies or credentials**.
   Non-GET endpoints remain inventory-only.
3. ffuf checks safe, directly discovered **GET paths** at the root and enumerates
   root plus up to two newly discovered parent directories. Unsafe action verbs
   (e.g. logout/delete/checkout/transfer), encoded paths, unexpected syntax,
   and non-GET-only routes are never added to direct-follow-up wordlists.
   ffuf never replays discovered query values or fuzzes parameter values.
4. A shared planning budget reserves up to **24 crawled pages + 56 ffuf
   candidates = 80 planned operations** across the sequential phases.
   Both subprocesses cap their native rate at **2 requests/s**; a gap between
   phases prevents a sudden burst. Press **Ctrl+C** to stop the subprocess
   tree and skip remaining passes.

**Important limits:** The 80-operation figure is a *planning bound*, **not**
a hard network-level request ceiling: Katana's page cap does not count every
auxiliary request, and remote redirects/proxies or scanner retries may otherwise
affect traffic. Do not interpret this as guaranteed total HTTP requests or as a
shared limiter across independent PenX scanner selections. The 2/s caps apply
to each native process, which this mode executes **sequentially**, not to all
other concurrently running PenX instances. ffuf follows no redirects in this
profile, and it uses only GET. The mode does not test SQLi, XSS, access control,
authorization bypass or other vulnerabilities automatically.

An inventory is stored locally under `data/endpoints/<sha256-prefix>.json`
for the single normalized origin. Repeated authorized mapping runs merge
deduplicated endpoint metadata, but **historical entries never authorize fresh
network probes**. Only URLs validated from the current complete crawl
determine ffuf follow-ups. Treat even URL *paths* as potentially sensitive:
the file is local data, should not be committed, and should be deleted when
no longer required. Incomplete or cancelled scanner runs are marked partial;
their missing findings are not evidence of a secure endpoint.

### Optional native web scanner adapters

The [1] New Scan tool picker also provides [7] Nuclei, [8] ProjectDiscovery
httpx, [9] ffuf, [s] passive Subfinder, [c] same-host Katana and [d] TLS check.
Standard presets [a] and [n] keep their bounded legacy behavior; [x] selects
all 12 available scanner adapters. Nuclei, ffuf and Katana require explicit
confirmation **before any selected scanner starts**. The LLM cannot dispatch
these scanners through arbitrary tool commands. Discovered subdomains are
inventory only, not automatic scan targets. [b] remains the Back alias.

`PenX.exe --setup-native` is an **opt-in**, SHA256-verified native Windows
binary installer for x64. Native scanner paths can also be supplied by private
`.env` entries `PENX_NUCLEI_PATH`, `PENX_HTTPX_PATH` and
`PENX_FFUF_PATH`, `PENX_SUBFINDER_PATH` and `PENX_KATANA_PATH`.
TLS checks require no external executable. The dedicated [e] mapping mode
also checks selected safe paths discovered in the current crawl. The ordinary
[9] ffuf adapter remains a root-only wordlist check. The simple built-in ffuf wordlist is capped to a few dozen
single-origin GET requests. Optional `PENX_FFUF_WORDLIST` accepts up to 80
safe relative paths. All scan profiles have fixed timeouts/concurrency and
do not accept arbitrary user- or model-supplied CLI flags.

Scan output is reduced to structured JSONL evidence. A template match or
HTTP result is only a lead, not proof that an exploit is possible. Template
downloads/updates are controlled by the upstream installation; PenX disables
automatic update checks during individual Nuclei/httpx scans.

## Printable PDF options

PDF reports use a white, readable A4 layout by default. Set
`PENX_PDF_THEME=dark` for the classic dark PenX appearance.

The technical PDF summarizes historical model output rather than printing
the full transcript. The original text remains in the saved HTML report.
Set `PENX_PDF_AI_APPENDIX=compact` or `full` to include it in new PDF exports.
Existing report files are unchanged until regenerated from history.
