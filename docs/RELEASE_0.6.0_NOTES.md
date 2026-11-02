# PenX v0.6.0 — Windows + Kali/Linux

This release introduces the first cross-platform packaged release of PenX from one
Python source tree. Windows remains supported, and an amd64 Debian package and
Linux portable archive join the established Windows installer and ZIP.

## Changes
- **Linux/Kali:** Python source, portable amd64 and installable `.deb` builds;
  XDG user data, private first-run `.env` (`0600`), Linux CLI diagnostics.
- **Real scanner support:** Native discovery and dispatch for Nmap, Nikto,
  WhatWeb, Nuclei, ProjectDiscovery HTTPx (`httpx-toolkit`), ffuf, Katana,
  passive Subfinder, plus built-in HTTP/DNS/TLS and combined endpoint mapping.
- **Better process isolation:** Linux PyInstaller builds restore the original
  shared-library loader environment when launching system scanner binaries.
- **Reproducible verification:** CI builds the actual Linux release package,
  installs it, and runs controlled Kali localhost scanner acceptance before
  the Windows release publisher includes all platform assets.
- **Local AI and reports:** Linux field testing included local-model full
  assessment and JSON/SARIF/HTML/PDF exports. See
  [Linux acceptance report](https://github.com/spk-c/PenX/blob/main/docs/LINUX_ACCEPTANCE_2026-11-02.md).

## Downloads and checksums
- Windows: `PenX-Setup-x64.exe` and `PenX-Windows-x64.zip`, checksum `SHA256SUMS.txt`.
- Linux amd64: `penx_0.6.0_amd64.deb` or `PenX-Linux-x86_64.tar.gz`,
  checksum `SHA256SUMS-Linux.txt`. Debian dependencies must be compatible.
- Source archives on GitHub are **not** packaged executable builds.
- Neither operating system's binary bundles third-party security scanners
  or AI model weights. Use authorized targets only.

## Acceptance status — NOT SIGNED OFF
Eleven Kali scanner adapters passed real locally isolated end-to-end checks
with evidence and machine-readable reports. Owner-authorized passive WHOIS and
Subfinder checks, and local AI/SQLite/report field checks, were also performed
on a Kali VM. These do not establish accuracy on arbitrary live targets.
Independent Windows/Npcap scanner hardware checks, ARM64 runtime builds,
other distros, real-world upgrades and cold-starts, interactive browser-layout
review, and all external enrichment paths remain **NOT SIGNED OFF**. The
Windows installer is not Authenticode-signed. Treat AI findings as reviewable
observations, not automatically verified vulnerabilities.
