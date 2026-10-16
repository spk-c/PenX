# PenX — final refactor acceptance and remaining implementation gates

Updated 16 October 2026. **Status: NOT SIGNED OFF.** This is a reproducible acceptance worksheet, not proof that the full refactor is finished. For code-level implementation details and committed regression tests, see [REFACTOR_PROGRESS.md](REFACTOR_PROGRESS.md).

## Acceptance rules

1. Record the Git commit SHA, OS, Python version, tool versions, installer build, database fixture source, executed commands and captured output for every gate.
2. Test **only systems the operator owns or explicitly has permission to scan**. Never run real active scanners from CI against third-party hosts.
3. Never migrate a production database to generate acceptance evidence. Use a consistent, verified-restorable backup copied to an isolated fixture. Never auto-resolve duplicated summary records.
4. A CI success is evidence only for the cases actually exercised. A skipped/missing/manual test is **not passed**.
5. Mark the full refactor complete only after all applicable code, compatibility, Windows hardware, recovery and report criteria pass, and a maintainer signs off.

## Remaining technical tasks

| Package | Definition of Done / independent verification | Evidence to attach |
| --- | --- | --- |
| Pk02 Settings | Exhaustive `METATRON_*` to `PENX_*` precedence map; portable read-only and Unicode path smoke on Windows | Matrix of tested legacy keys, command output and paths |
| Pk03 Evidence | Versioned persisted source anchors round-trip, explicit historical-unverified semantics, independently revalidate against retained raw source when available; reject malformed/forged data | SQLite/MariaDB fixtures and tampered-anchor tests |
| Pk04 Scanner runner | Complete separation of adapters from process orchestration; real cancel/timeout/descendant kill for Nmap, Nikto, Nuclei, ffuf, Katana, Subfinder and other registered modes | Sanitized child process tree + exit-code logs |
| Pk05 Scanner integration | Exercise all 12 registered choices, presets, cancel/back, passive-only and consent on Windows, with authorized disposable targets | Per-mode matrix and explicit authorization evidence |
| Pk06 Storage | Inventory/remove only proven-unused legacy facades, maintain legacy positional API until consumers and compatibility tests are migrated | AST/import inventory, caller audit and cross-backend tests |
| Pk07 Schema | Restore production-shaped *sanitized* SQLite WAL and MariaDB backups onto isolated test servers; rehearse migrations and failing/duplicate upgrade rollback | Backup/restore checksum, migration versions, audit output |
| Pk08 Model | Fully injected source/model clients incl. cleanup/timeout/retries with stable fail-closed auto/strict/off behavior | Offline failures matrix including timeouts/malformed/empty payloads |
| Pk09 CLI | Separate remaining terminal presentation from use cases, keep Esc/back and pause-on-failure semantics | Reproducible keypress simulations and Windows manual UI checks |
| Pk10 Reporting | Long real-world-size HTML/PDF/JSON/SARIF parity; crash/power-loss manifest recovery and deletion/retry checks | Rendered output inspection, crash injection/recovery logs |
| Pk11 Packaging | Real Windows per-user installer, first run, upgrade, rollback, repair/uninstall and Npcap UAC behavior; signed release verification if release signing is required | Windows VM/physical machine log, hashes and rollback screenshots |
| Pk12 Quality | Incrementally broaden Ruff/mypy to all maintained Python modules, Python 3.10–3.13 Windows/Linux matrix, dependency/toolchain lock review and representative benchmarks | GitHub workflow links, type/lint report and baseline comparisons |
| Pk01 Baseline | Reproducible end-to-end measurement and failure inventory using fixed approved fixtures | Baseline run log, wall time/memory and environment metadata |

## Standard CI validation (on each reviewed PR)

- `python offline_tests.py` on Windows and Ubuntu, including new regression suites.
- The repository's configured Ruff, mypy, import inventory, benchmark-threshold and package gates.
- Real MariaDB integration job when storage changes, alongside isolated SQLite/WAL recovery tests.
- Windows portable EXE/installer build and smoke when bootstrap/CLI/packaging changes.
- Security audit including dependency, secret and CodeQL checks.

Review the *current head SHA* for each workflow run. Do not count green workflows from a prior commit.

## Field test record template

For each remaining item add a short entry with:

- **Gate / owner:** package and maintainer responsible
- **Commit / build:** immutable SHA and artifact checksum
- **Environment:** OS, Python, tools, DB engine, relevant settings (secrets redacted)
- **Fixture:** authorized disposable target or restored sanitized backup
- **Procedure:** exact reproducible steps
- **Expected / actual:** observable output and screenshots/log references
- **Result:** PASS / FAIL / BLOCKED / NOT RUN
- **Rollback:** proof that customer state is not changed or can be restored
- **Sign-off:** maintainer and date

Until these entries exist, the remaining work is **unverified**, not complete.

## Source-provenance revalidation (Pk03)

The versioned metadata parser restores bounded historical evidence anchors but
does not restore the adapter's raw text. When the operator retains a separate,
trusted raw scanner capture, call
`penx_app.domain.evidence.revalidate_persisted_evidence(stored, originals)`,
where `stored` is `ScanResult.from_metadata(...)` and `originals` contains the
matching original `ScannerResult` objects. The validator refuses missing,
duplicated, failed or mismatched original sources; it never promotes restored
metadata to independently observed evidence by itself.

Offline tests in `tests/test_persisted_evidence_revalidation.py` cover this
check without fetching a target or a third-party API. **Pk03 field sign-off
still requires actual independent source captures and persisted SQLite/MariaDB
fixtures; tests of fabricated fixtures alone do not satisfy that criterion.**

## Terminal cancellation review status (16 October 2026)

Terminal Ctrl+C now reaches an opt-in event at the scanner selection boundary;
the structured dispatcher and eight native subprocess-capable wrappers can
consume it. A cancelled interactive selection does not proceed to assessment
creation, even if some earlier adapters completed. This is tested with
synthetic adapters and a simulated SIGINT. It is **not** independent
Windows/real-scanner confirmation; Pk04 and Pk05 remain NOT SIGNED OFF.

## Incremental Ruff/mypy coverage extension (Pk12)

The pure scanner-selection policy, CLI cancellation token boundary,
Esc/Back navigation reader and scanner registry have dedicated F401 and
mypy CI coverage, guarded by offline regression tests. Remaining Pk12
criteria still require complete maintained-tree coverage, a reviewed
Windows build toolchain lock and independent field benchmarks; this is
**not** a final sign-off.

## Pk08 catalogue-client test coverage (16 October 2026)

NVD, OSV and GitHub Advisory calls now accept independent per-call HTTP
clients, with fixed provider URLs, bounded timeouts and redirects disabled.
Injected NVD lookups bypass production LRU/disk cache state. The discovery
orchestrator accepts call-local source, priority and vendor lookups. Offline
contracts exercise rate limiting, unknown results, failure warnings and
absence of real network calls. Production-network and model-lifecycle field
acceptance remain **NOT SIGNED OFF**.

## Python network adapter cancellation (Pk04/Pk05)

The four Python-network adapters accept per-call scan cancellation tokens
and refuse to publish evidence returned after cancellation. Tests use
local mocks only; no real host, third-party service or database is accessed.
Blocking-call interruption is **not** guaranteed, especially for WHOIS.
Run real Windows/authorized-target timeout and child-process-tree field
tests before marking Pk04/Pk05 complete. No field sign-off is asserted.

## Tracked outstanding issues (16 October 2026)

The full refactor remains **NOT SIGNED OFF**. To avoid treating published
v0.4.7 binaries as proof of hardware/field acceptance, follow the dedicated
checklists: [Windows/scanner + Npcap](https://github.com/spk-c/PenX/issues/11),
[DB restores/evidence/report parity](https://github.com/spk-c/PenX/issues/12),
[model/CLI refactor](https://github.com/spk-c/PenX/issues/13), and
[static typing, legacy compatibility and benchmarks](https://github.com/spk-c/PenX/issues/14).
Only close each issue after independent evidence is attached and reviewed.
