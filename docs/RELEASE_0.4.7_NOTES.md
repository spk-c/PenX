# PenX v0.4.7 – refactor stability maintenance

**Published stable Windows release:** [v0.4.7](https://github.com/spk-c/PenX/releases/tag/v0.4.7). The tagged Windows build succeeded and published `PenX-Setup-x64.exe`, `PenX-Windows-x64.zip`, `SHA256SUMS.txt` and `CVE-QUALITY.json`. This confirms published automated build artifacts, **not** full hardware/field refactor sign-off.

## Changes since v0.4.6

- Cooperative CLI scanner cancellation reaches native and Python network
  adapters; cancelled responses do not become completed findings.
- NVD/OSV/GitHub Advisory research supports injectable, isolated source clients.
- Broader Ruff/mypy coverage of scanner and CLI boundaries.
- Windows CI runs the Inno Setup uninstaller and verifies user data survives.
- All static PENX_/METATRON_ setting keys have a precedence test matrix.
- Isolated MariaDB transactional backup/restore tests preserve synthetic
  assessment data and uniqueness constraints.
- The field-evidence PowerShell helper is smoke-tested on Windows CI.

## Unfinished field acceptance

Physical Windows/Npcap/UAC behavior, approved real-target scanner cancellation,
historical sanitized SQLite/MariaDB restore and rollback, manual inspection of
long generated PDF reports and representative local benchmarks remain
**NOT SIGNED OFF**. Do not label this maintenance release a 100% completed
refactor or upload customer records and credentials for these tests.
