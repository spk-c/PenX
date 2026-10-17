# PenX v0.4.8 – post-0.4.7 security and reliability fixes

**Published stable Windows release:** [PenX v0.4.8](https://github.com/spk-c/PenX/releases/tag/v0.4.8) (17 October 2026). The verified Windows release workflow [39020663160](https://github.com/spk-c/PenX/actions/runs/39020663160) published the Windows installer, portable ZIP, SHA-256 checksums and CVE quality report. This confirms the automated release pipeline, **not** physical hardware or field acceptance.

## Changes since v0.4.7

- Scanner input validation, strict legacy evidence contracts, source and LLM output validation, bounded subprocess behavior.
- Consistent SQLite snapshots for session reports, training exports and review packages.
- Serialize per-session report publishing/deletion and correction/evaluation/finding operations.
- Bounded, specific SQLite-BUSY retry for safe session lock acquisition, never replay commits.
- Disallow model-directed arbitrary external search by default; optional CVE-ID-only research via `PENX_ALLOW_MODEL_WEB_SEARCH=on`. The default is **off**.
- Harden malformed NVD configuration parsing and bound external page retrieval to 512 KiB of public HTTPS without redirects.
- Correct no-op MariaDB edit feedback, preserve literal `%s` inside SQLite SQL, reject malformed scanner argv and nontext evidence, serialize full-session deletion, make evaluation deletion status honest, and bound report manifest JSON reads.

The source audit fixes were merged in PRs #40 and #41, with the 0.4.8 version bump in PR #42. The annotated release tag points to reviewed commit `db3c96236b6330f6c716b8d96da0b796101d92e8`.

## Release verification and outstanding field acceptance

The existing `.github/workflows/release.yml` workflow completed successfully on GitHub Actions: [Windows Release run 39020663160](https://github.com/spk-c/PenX/actions/runs/39020663160). It ran the offline regression suite, packaged the complete PyInstaller Windows ZIP, tested the Inno Setup installer and installed EXE startup, and published four files:

- `PenX-Setup-x64.exe` — SHA-256 `782149079b5533e4bfd6098551ead95b66957ab5e7bcceebf683052e281f4b5c`
- `PenX-Windows-x64.zip` — SHA-256 `ed8ea9aa6c0653396d0e3fcd091cb4a01d2aa1130e17f753817eb519d4237071`
- `SHA256SUMS.txt` — accompanying hashes
- `CVE-QUALITY.json` — synthetic quality fixture report

The runtime dependencies were installed using the repository's hash-locked requirements. These results do **not** certify all Windows UAC/Npcap scanner integrations, per-user upgrade and rollback, production-shaped DB backup recovery or long PDF visual checks.

**Field acceptance status: NOT SIGNED OFF.** On an authorized disposable Windows VM/host, complete the manual tests and record PASS / FAIL / NOT RUN evidence in `docs/FIELD_ACCEPTANCE.md` and `docs/REFACTOR_ACCEPTANCE.md`. Never treat the newly published release or its automated smoke tests as physical sign-off.
