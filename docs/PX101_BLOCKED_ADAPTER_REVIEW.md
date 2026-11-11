# PX-101: project-bound scanner adapter review matrix (#189)

**Status: review pending. None of the disabled adapters below has been
approved for project mode.** This is a safety inventory and acceptance
contract, **not** an operator sign-off, scanner rollout, or authorization to
scan a third-party host. No live tests or real target scans were performed.

The existing project dispatch policy permits **only** `4` HTTP headers,
`5` DNS, `8` httpx, and `d` TLS, plus the separately checked passive
profile. It requires a concrete approved target, scoped duration/rate budget,
sequential execution, and a fresh approval recheck before supported outbound
requests. Everything else remains rejected **before subprocess or network
I/O**, including WHOIS (key `2`) and mixed safe/blocked plans.

## Blocked adapter inventory and independent acceptance requirements

| Key | Adapter | Review needed before any project opt-in |
| --- | --- | --- |
| `1` | Nmap | Strict single approved host/IP; explicit destination ports; audit `-sC`/service-script egress; per-operation budgets and process-tree cancellation |
| `2` | WHOIS | Registry queries may contact unrelated provider endpoints; domain-only policy, bounded lookup, provider egress review, cancellation and fresh authorization before each request |
| `3` | WhatWeb | HTTP(S) authority and port pinning, both script/EXE and Python fallback branches; redirects, timeouts, and request budgets |
| `6` | Nikto | Explicit approved origin, HTTPS/port preservation, no host-changing redirect or unexpected downstream target; subprocess deadline and descendants |
| `7` | Nuclei | Template-driven network destinations and redirects; enforce exact per-request approved scope and rate, prevent out-of-scope template interactions |
| `9` | ffuf | Bounded wordlist/fan-out, fixed host:port/scheme, redirect refusal and budget across every attempted URL; process-tree abort |
| `s` | Subfinder | Third-party passive sources and discovered subdomains are **never** automatic approved targets; provider requests, cancellation and per-call revocation |
| `c` | Katana | Crawl/redirect/embedded resource link expansion must not leave approved origin; strict discovered-host policy, process-tree cancellation and maximum requests |
| `e` | Endpoint mapping | Katana-to-ffuf chained discovery; every proposed directory/URL needs its own approved-origin, budget and revocation checks; never reuse stale inventories |

These are *required properties to prove*, not verified claims about the
external executables. A wrapper that merely filters printed output is
insufficient if the underlying scanner can already contact extra hosts.

## Per-adapter minimum contract before enabling

1. **Target grammar:** single canonical approved host or IP, explicit allowed
   scheme and port, reject path/userinfo/unknown port ambiguity and wildcard
   or CIDR expansion; no implicit DNS-derived or discovered target approval.
2. **Effective egress:** prove no unapproved external destination or redirect
   is contacted (including resource fetches, provider APIs, templates and
   auxiliary subprocesses), using disposable loopback positives and negatives.
3. **Budget and cancellation:** count real outbound attempts against the
   approved per-run rate and timeout budget; kill the complete process tree
   on timeout/cancel, do not silently ignore failure or partially collect.
4. **Revocation:** re-query the approved asset immediately before every
   eligible outbound action, including retries and queued discoveries; abort
   safely after cancellation/revocation. An in-flight OS operation cannot be
   retroactively stopped by a database flag.
5. **Evidence:** retain COMPLETE/PARTIAL/FAILED classification and provenance
   without treating a blocked or missing scanner as a verified finding.
6. **Independent acceptance:** separately review Windows/Kali binaries,
   port/IPv6/redirect examples, real tool flags and cancellation in
   operator-owned disposable environments; mark external/field work
   **NOT RUN** until actual evidence is recorded.

## Automated safeguards in this slice

`PROJECT_REVIEW_REQUIRED_SCANNERS` explicitly tracks all nine blocked
tool-menu keys, including previously omitted WHOIS. The offline
`tests/test_px101_blocked_adapter_inventory.py` tests require every
`TOOLS_MENU` key to be either reviewed-safe or explicitly blocked,
verify that all blocked/mixed scanner plans fail before any project scope
lookup, network access or subprocess, and do not run scanner binaries.

Existing `tests/test_project_dispatch.py` covers granted safe adapters,
repeated approval checks, revocation, port restrictions, mocked HTTP
redirect refusal and subprocess limits. These tests **do not** satisfy
the per-adapter review contract above.

**Still blocked:** PX-102 automatic job resume and PX-105 unattended
recurring scans. Do not change their default until scope review,
recovery/rollback and independent operator acceptance are documented.

See [PROJECT_SCOPE.md](PROJECT_SCOPE.md),
[ROADMAP.md](ROADMAP.md),
[FIELD_ACCEPTANCE.md](FIELD_ACCEPTANCE.md) and
[issue #189](https://github.com/spk-c/PenX/issues/189).
