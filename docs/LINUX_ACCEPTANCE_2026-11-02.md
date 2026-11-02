# Linux/Kali acceptance – 2026-11-02

PR #119 was exercised on an actual VMware Kali Linux 2026.3 amd64 VM
(kernel 7.1.5+kali-amd64, glibc 2.43), using Python 3.13.18. Application
and scanner processes ran as an ordinary user. These are development-port
acceptance results, not a v0.6.0 release certification.

## Completed checks

- Full Kali regression suite after the final fixes: 1,637 tests, no failures,
  three platform-specific skips.
- Linux PyInstaller build, Debian package and portable archive; installation,
  XDG configuration with mode `0600`, and removal/reinstallation preserving
  the user's configuration byte for byte.
- Ten real scanner adapters in both source and installed Debian modes:
  Nmap, WhatWeb, HTTP headers, Nikto, Nuclei, ProjectDiscovery HTTPx, ffuf,
  Katana, endpoint mapping and TLS. All returned `COMPLETE`, `evidence=True`,
  and valid JSON/SARIF against owned loopback fixtures. Nuclei used one
  controlled fixture template. DNS additionally passed with the installed
  CLI in isolated network and mount namespaces; the host resolver was not
  modified.
- Live passive Subfinder discovery for a domain explicitly authorized by
  its owner. Native and packaged PenX runs produced the same three-host
  inventory. Discovered hosts were not actively scanned.
- Live WHOIS exposed missing `python-whois` package data in the frozen
  bundle. Both build configurations now collect that data. The rebuilt
  Linux binary passed the authorized WHOIS query without manually adding
  files; packaged CI checks also require the public suffix data file.
- Actual local NInfer `qwen3.8-27b` reviews and full assessments with strict
  structured JSON, self-review, SQLite save/reload and HTML/PDF export.
  Full assessments passed with normal VM networking and with no external
  network route, using a local socket relay to the model on the host.
  Inputs were synthetic and external source enrichment was disabled.
- SQLite writer killed during an open WAL transaction: committed data
  survived, the incomplete transaction rolled back, and `integrity_check`
  returned `ok`. Backup/restore and migration regressions also passed.
- Empty, short and 38-page synthetic reports generated successfully.
  PDFs were rendered and visually checked, with the long report's text
  bounding boxes checked against every page. HTML content contracts passed.

The installed-WhatWeb acceptance environment exposed a test that assumed
the scanner was absent. The fallback test now explicitly isolates that
condition. Linux reports also use cross-platform branding, and HTTPx
discovery restores the original loader environment like scanner execution.
Relative XDG data directories are ignored in favor of the standard fallback.

## Remaining limits

Bare-metal Kali, ARM64 runtime builds, other distribution field runs,
reboot/cold-start testing, different-version package upgrades, external
source enrichment/cloud-model assessments and interactive HTML browser
layout acceptance remain unverified. SQLite crash recovery is not a promise
to repair arbitrary corruption without a backup. Loopback integration tests
do not establish vulnerability-detection accuracy or production readiness.

No release tag or published release artifact was created for this acceptance.
