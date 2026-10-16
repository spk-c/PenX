# PenX refactor — verified progress and remaining gates

**Last updated:** 16 October 2026 · original plan baseline `93f9195` ·
modularization baseline `7994b6202`.

The original plan estimates 32–52 person-days. The incremental changes
listed below are merged and tested. **All three P1 milestones are merged
and CI-verified** (#121–#129, shipped as the v0.4.6 release), and the P2
reproducibility work (hash-locked dependencies, the calibrated benchmark
gate, legacy shim retirement and the broadened Ruff/mypy gates) is
complete and verified by the offline regression suite, but the full
refactoring Definition of Done is **not yet satisfied**: the manual/field
sign-off gates below still need independent evidence. A green CI check
verifies the work that was run; it does not prove all manual scanner,
migration and release cases.

## Implemented, merged and verified

- [#107](https://github.com/SLP-DEV1/PenX/pull/107): package startup,
  structured scanner metadata validation, connection ownership for correction
  rules, shared reviewed report view, and assessment recovery contracts.
- [#111](https://github.com/SLP-DEV1/PenX/pull/111): evaluation/distillation
  storage queries isolated from Markdown report rendering, with legacy facades.
- [#112](https://github.com/SLP-DEV1/PenX/pull/112): authoritative scanner
  result projection and legacy reader extracted from `scanners/tools.py`,
  recursively discovered offline tests, Python 3.10–3.12 compatibility checks.
  Existing Windows/Linux CI covers Python 3.13.
- [#113](https://github.com/SLP-DEV1/PenX/pull/113): history/report-management
  and edit/delete terminal dialogs extracted with call-time injected ports.
  The legacy `penx` public functions and test patch points remain.
- [#114](https://github.com/SLP-DEV1/PenX/pull/114): architecture guard tests
  and synthetic, no-network Windows/Linux benchmark JSON artifacts.
- [#115](https://github.com/SLP-DEV1/PenX/pull/115): untrusted evaluation
  response and distilled-rule parsers moved into the pure domain layer.
- [#116](https://github.com/SLP-DEV1/PenX/pull/116): atomic external
  evaluation import with the automatically generated correction records,
  SQLite rollback injection and live MariaDB integration regression.
- [#117](https://github.com/SLP-DEV1/PenX/pull/117): bounded scanner
  subprocess stdout/stderr collection in quiet and live modes; incomplete
  or timed-out output cannot become completed evidence.
- [#118](https://github.com/SLP-DEV1/PenX/pull/118): restore previous
  HTML/PDF report when the second publication fails (I/O exception recovery,
  not full crash-atomic multi-file transactions).
- [#119](https://github.com/SLP-DEV1/PenX/pull/119): evaluator import/export,
  training and rule-distillation dialogs extracted from the CLI with
  preserved menu behavior and legacy call-time injection points.
- [#120](https://github.com/SLP-DEV1/PenX/pull/120): synthetic legacy
  SQLite WAL backup/restore fixture, idempotent migration and failed-upgrade
  rollback/retry contract on Windows/Linux.
- [#121](https://github.com/SLP-DEV1/PenX/pull/121): replace the shared scan
  diagnostic flag with an explicit per-attempt `ScanOutcome`, preserving the
  deliberate pause-on-failure behavior and the menu acknowledgement input
  sequence.
- [#122](https://github.com/SLP-DEV1/PenX/pull/122): independent per-format
  publication of saved-session report formats — one persisted session
  snapshot for all exports, independent per-format outcomes and diagnostics,
  and per-format HTML/PDF export results in the history view.
- [#123](https://github.com/SLP-DEV1/PenX/pull/123): typed `ScanResult`
  outcomes transported through all twelve active menu adapters on the stable
  registry contract, preserving the injected formatter dict contract.
- [#124](https://github.com/SLP-DEV1/PenX/pull/124): PenX startup regression
  tests from Unicode and space-containing installation paths.
- [#125](https://github.com/SLP-DEV1/PenX/pull/125): per-user Windows Inno
  Setup installer and opt-in GitHub release updater with versioned
  installed-mode paths, update consent, SHA-256 verification, user-data
  migration docs and an Inno Setup CI smoke build; shipped as the v0.4.6
  release.
- [#126](https://github.com/SLP-DEV1/PenX/pull/126): semantic validation of
  reviewed findings across HTML, PDF, JSON and SARIF report formats.
- [#127](https://github.com/SLP-DEV1/PenX/pull/127): Ruff and mypy CI gates
  extended to the extracted refactor module boundaries.
- [#128](https://github.com/SLP-DEV1/PenX/pull/128): trusted scanner
  duration, native child exit codes and diagnostics captured at the adapter
  execution boundary and retained as bounded typed telemetry until the
  presentation boundary.
- [#129](https://github.com/SLP-DEV1/PenX/pull/129): structured
  `auto`/`strict`/`off` analysis-mode and passive model-scope contracts
  verified against the pipeline.

These changes passed applicable GitHub Actions gates before merging:
Windows/Linux offline regression suites, Windows portable EXE smoke, Security
audit, MariaDB integration, Python compatibility, or distribution checks
according to the changed paths. CI artifacts provide benchmark samples
with OS/Python/commit metadata. Benchmark numbers are **not** comparable
unless hardware, Python, workload and environment match.

## Status against all twelve original work packages

| Package | Verified implementation | Remaining acceptance work |
| --- | --- | --- |
| 01 Baseline | Offline harness, synthetic fixtures, CI and benchmark artifact generation | Real representative scan/export measurements, failure inventory and reproducible backup restoration |
| 02 Settings | Explicit `Settings`, `RuntimeOptions`, bootstrap and portable path resolver; `METATRON_*` fallback pinned at `settings.load_settings`, `config.setting`, `first_run_setup` import-time capture and `scanner_runtime` lookup (PR #171, merged) | Test all remaining `METATRON_*` legacy settings and real portable read-only installations |
| 03 Scanner results | Typed `ScanResult` transported through all twelve adapters (#123); trusted duration, exit codes and diagnostics captured at the adapter boundary (#128); isolated legacy text reader; bounded `EvidenceRecord` attached at the adapter execution boundary and carried through the `ScannerOutput`/recon formatting boundary (PR #171, merged) | Bounded anchors persist in versioned scan metadata; real source revalidation and field sign-off remain open |
| 04 Scanner runner | Sequential runner, consent and bounded stdout/stderr capture (#117); caller-cancellation and live-timeout process-tree termination pinned in tests (PR #171, merged) | Field verification of cancellation under live scans, full adapter separation and field scanner loads |
| 05 Scanner integration | Twelve registered menu choices on the stable registry contract with typed outcomes (#123) and restricted model command allowlist | Confirm all preset/consent paths on Windows in the field |
| 06 Repositories | `SessionRepository`, `SessionSnapshot`, correction rules, eval repository and atomic import (#116); named `FixRecord`/`ExploitRecord`/`CorrectionRecord`/`EvaluationRecord` records with explicit column lists on every storage read boundary (PR #171, merged) | Audited legacy facade retirement |
| 07 Schema and backends | SQLite migration guard, MariaDB CI, synthetic WAL backup/restore and interrupted upgrade retry (#120) | Real older customer-safe upgrade rehearsal and manually applied MariaDB DDL parity checks |
| 08 Model and intelligence | `analysis_pipeline`, `llm_client`, pure evaluator parser, review/CVE fixtures, structured `auto`/`strict`/`off` and passive model-scope contracts verified (#129) | Fully isolated model/source client injection and exhaustive `auto/strict/off` failure-contract tests |
| 09 Application / CLI | `assessment_service`, history/edit and evaluator/rule review dialogs extracted (#113, #119); explicit per-attempt `ScanOutcome` replacing the shared diagnostic flag (#121); shared recon-choice helper and a recon-only menu step decoupled from the full scan flow (PR #171, merged) | Replace remaining interactive coupling without losing error acknowledgement |
| 10 Reporting | `ReportView`, HTML/PDF/JSON/SARIF, pure review Markdown, failure rollback during two-file publication (#118), independent per-format publication with per-format outcomes (#122), cross-format review validation (#126), crash-detectable multi-file publication manifest (crash-detectable `in_progress` state → idempotent re-run) | Manual long-PDF review |
| 11 Packaging | Canonical `penx_app`, compatible launcher, installed `python -m penx`, automated EXE smoke, Unicode/spaced startup tests (#124), per-user installer with verified updater and versioned installed-mode paths (#125) | Real first-run setup, Npcap/UAC, signed release and installer rollback checks |
| 12 Quality/release | Recursive test discovery, Python 3.10–3.13 checks, architecture guard, synthetic benchmark CI with a representative HTML/PDF export workload and calibrated performance threshold gate (`scripts/benchmark_thresholds.json`, checked in CI), Ruff/mypy gates on the extracted refactor boundaries (#127) broadened to 16 F401 modules and 23 mypy module paths (27 files), the import-inventory gate (`scripts/import_inventory.py --check`) with 58 legacy shims retired, hash-locked transitive dependencies (`requirements.lock.txt`, CI hash-checked install, offline lock test, installer wiring) | Further type/lint coverage across the wider `penx_app` tree, full Python/OS suites |

## Required remaining work in priority order

**P0 data-integrity and scanner-output milestones closed:** #116 provides
transactional evaluation imports with SQLite and MariaDB rollback tests;
#117 bounds subprocess capture and preserves incomplete-output status. These
checks do **not** replace manual real-scanner and system-failure verification.

**P1 milestones — closed:**

1. **P1 typed scan/application flow — closed.** #121 replaces the shared
   diagnostic flag with an explicit per-attempt `ScanOutcome` while retaining
   the deliberate pause-on-failure behavior; #123 transports typed
   `ScanResult` outcomes through all twelve adapters on the stable registry
   contract; #128 preserves trusted scanner duration, exit codes and
   diagnostics as bounded typed telemetry; #129 verifies the structured
   `auto`/`strict`/`off` and passive model-scope contracts. Field
   verification of cancellation and child-process-tree behavior remains
   under package 04.
2. **P1 report parity — closed.** #122 publishes each saved-session report
   format independently from one persisted session snapshot with
   independent per-format outcomes, and #126 validates reviewed findings
   semantically across HTML/PDF/JSON/SARIF. Crash-detectable multi-file
   publication is implemented in both `generate_session_reports` and
   `publish_reports`: every batch is bracketed by an atomic per-session
   manifest that records `in_progress` before any report file is written
   and `complete`/`partial` only after the last `os.replace`/`os.link` has
   published, so a mid-batch process crash leaves a detectable `in_progress`
   state that recovers by re-running the idempotent publication
   (`test_report_crash_atomic.py`).
3. **P1 upgrade/release sign-off — closed in CI; manual field sign-off
   outstanding.** #124 covers Unicode/spaced startup paths; #125 ships the
   per-user installer and verified updater (released as v0.4.6) with Inno
   Setup CI smoke builds; #120 provides the synthetic WAL recovery and
   failed-upgrade retry contracts. Remaining manual evidence: real
   backup/recovery rehearsals on customer-shaped data, explicitly migrated
   MariaDB, Windows setup/uninstall/rollback on real hardware, actual
   scanner detection and signed release assets.

**Remaining open work:**

4. **P2 reproducibility — merged and CI-verified; hardware acceptance pending.** Hash-locked transitive dependencies
   are now provided and tested: `requirements.lock.txt` pins every direct
   and transitive package with sha256 hashes, is verified by a fresh
   `pip install --require-hashes` install in CI (Windows + Linux) and an
   offline consistency test (`tests/test_dependency_lock.py`), and the
   Windows installer installs from the lockfile (falling back to
   `requirements.txt`). The synthetic benchmark now also renders the
   representative HTML/PDF export workload through the application export
   path and is checked in CI against calibrated performance thresholds
   (`scripts/benchmark_thresholds.json`), catching catastrophic
   regressions on comparable hardware. Legacy compatibility shims are now
   retired: 58 of the 60 top-level `src/*.py` shims are removed (only
   `src/llm.py` and `src/app_paths.py` remain as pinned public entrypoints),
   `scripts/import_inventory.py --check` gates that no consumer still
   references a retired name, and `tests/test_repo_layout.py` asserts the
   on-disk shim set and the inventory check. The CI gates were broadened to
   match: the Ruff F401 gate now covers 16 extracted modules and the mypy
   gate 23 module paths (27 files) across the `penx_app` tree;
   `scripts/issue_triage.py` and the `windows_python_setup` bootstrap
   import checks now resolve legacy module names to their canonical
   locations. Verified locally by the full 83-suite offline regression run
   plus the Ruff/mypy gates; the packaged-EXE import smoke in CI re-verifies
   the bootstrap path on the next push. The four modules that still carried
   pre-existing mypy errors (`scan_trends`, `risk_assessment`,
   `structured_scan_evidence`, `analysis_pipeline`) have since been
   type-cleaned (missing variable annotations plus one mixed-type override
   dict) and now join the mypy gate, bringing it to 23 module paths (27
   source files) across the `penx_app` tree; verified by the full
   83-suite offline regression run and the 7 suites that exercise those
   modules.
5. **P2 model/orchestration DI (package 08) — merged in PR #171; further acceptance remains open.** `penx_app.analysis.llm`
   now builds one immutable `Settings` snapshot per `analyse_target` call
   and binds it to every model transport: `ask_llm(messages, settings=...)`
   resolves URL/models URL/base URL/model/API key/max tokens/timeout/top_k
   from the snapshot (module globals only when omitted), and
   `self_review(..., ask=...)`, `summarize_tool_output(..., complete=...)`
   and `run_tool_calls(..., summarizer=...)` accept call-time injected
   transports; the legacy facade passes bound versions through
   `AnalysisPorts` instead of module globals. Failure behavior is
   unchanged: transport errors return the existing `[!]`-prefixed strings
   and the pipeline still raises on empty, `[!]`, tool-budget-exhausted and
   (strict-mode) invalid-structured finals. New deterministic coverage in
   `tests/test_model_failure_contracts.py` (23 tests) pins the snapshot
   contract, the legacy-globals fallback, timeout/connection/HTTP/unexpected
   error mapping, self-review and summarizer failure contracts, and the full
   auto/strict/off matrix (valid structured report, auto fallback to text,
   strict `RuntimeError`). Three pre-existing fakes patching `llm.ask_llm` /
   `llm.run_tool_calls` (`test_cve_advanced.py`, `test_cve_discovery.py`,
   `test_scan_quality.py`) now accept the new kwargs. Verified locally:
   98/98 offline suites, Ruff and mypy clean on the changed files,
   `scripts/import_inventory.py --check` clean, benchmark threshold gate
   passed with no violations.
6. **P2 named storage records (package 06) — merged in PR #171; further acceptance remains open.** Every storage read
   boundary now returns typed NamedTuple records instead of anonymous
   tuples: `FixRecord`, `ExploitRecord`, `CorrectionRecord`
   (`session_repository.py`) and `EvaluationRecord`
   (`evaluation_repository.py`). `SessionSnapshot.fixes/exploits/
   corrections` are typed `tuple[<Record>, ...]`;
   `EvaluationRepository.load_evaluation_package()` returns
   `tuple[EvaluationRecord, ...]`; the legacy readers
   `get_fixes`/`get_exploits`/`get_corrections` (`db.py`) wrap the
   repository records. All storage SELECTs use shared explicit column
   lists (`FIX_COLUMNS`, `EXPLOIT_COLUMNS`, `CORRECTION_COLUMNS`,
   `EVALUATION_COLUMNS` in `db_backend.py`) instead of `*`, so public
   tuple layouts no longer depend on physical column order. Records are
   plain tuples: positional consumers (`row[3]`), `isinstance(x, tuple)`
   and tuple-equality assertions keep working; the new contract suite
   `tests/test_storage_records.py` (6 tests) pins physical-order parity
   and the legacy positional contract. All storage consumers were audited
   (`db_display`, `report_design`, `terminal_pdf`, `evaluation_packages`,
   `session_edit_dialog`, `risk_assessment`, `scan_trends`) — index-only
   access, no schema drift. Verified locally: 99/99 offline suites, Ruff
   and mypy clean on the changed files, `scripts/import_inventory.py
   --check` clean, benchmark threshold gate passed with no violations.
7. **P2 adapter evidence provenance (package 03) — merged in PR #171; further acceptance remains open.** `run_selected_structured`
   now attaches one bounded `EvidenceRecord` per adapter that actually
   produced evidence (kind `adapter_output`, `parser_version` 1, window
   0..min(2000, len) of the raw output) to the typed `ScannerResult`, and
   `ScannerOutput` and `format_recon_for_llm` carry the records through the
   formatting boundary into the recon `ScanResult`; `ScanResult.metadata()`
   round-trips deliberately do not fabricate records for stored adapters,
   and failed or blank adapters carry none. The new contract suite
   `tests/test_adapter_provenance.py` (6 tests) pins the attach, window
   bounds, blank/failed handling, formatting-boundary carry-through and
   the metadata round-trip contract. Verified locally: 100/100 offline
   suites, Ruff and mypy clean on the changed files,
   `scripts/import_inventory.py --check` clean, benchmark threshold gate
   passed with no violations.
8. **P2 scanner-runner cancellation coverage (package 04) — in progress on
   branch PR #171 (merged).** The existing
   `test_scanner_process_tree` suite pinned only the quiet-mode timeout
   path; a caller raising into `run_tool` (e.g. `KeyboardInterrupt`-style
   `BaseException` from the wait loop) and the live-mode timeout path had
   no coverage that the whole process tree is terminated and no threads or
   orphaned descendants are left behind. The new contract suite
   `tests/test_scanner_cancellation.py` (3 tests) pins: (a) a
   `BaseException` raised by the caller during the wait terminates the
   spawned parent *and* grandchild process tree with no worker threads
   leaked; (b) a live-mode timeout returns `PARTIAL` status with
   `evidence=False` and kills descendants; (c) `_terminate_process_tree` is
   idempotent for an already-exited process. Verified locally: 102/102
   offline suites, Ruff and mypy clean on the new file,
   `scripts/import_inventory.py --check` clean, benchmark threshold gate
   passed with no violations.
9. **P2 legacy `METATRON_*` fallback coverage (package 02) — in progress on
   branch PR #171 (merged).** The `METATRON_`
   namespace is retired only when every fallback boundary is pinned;
   `test_refactor_contracts` covered `load_settings` precedence but not the
   other three surfaces that still honor legacy names. The new contract
   suite `tests/test_legacy_settings.py` (4 tests) pins: (a)
   `load_settings` falling back to `METATRON_MAX_TOKENS`,
   `METATRON_VERIFY_SOURCES`, `METATRON_NVD_API_KEY` and
   `METATRON_TIMEOUT`; (b) `config.setting` honoring `METATRON_*` process
   environment with `PENX_*` winning when both are set; (c)
   `first_run_setup` import-time scanner-path capture honoring
   `METATRON_*` paths; (d) `scanner_runtime.find_runtime` resolving legacy
   `METATRON_RUBY_PATH`/`METATRON_PERL_PATH` overrides with per-value
   `PENX_*` precedence. Verified locally: 102/102 offline suites, Ruff
   and mypy clean on the new file, `scripts/import_inventory.py --check`
   clean, benchmark threshold gate passed with no violations.
10. **P2 interactive recon picker decoupling (package 09) — in progress
   on branch PR #171 (merged).** The full
   scan flow inlined the recon tool picker between the target prompt and
   session reservation, coupling the picker to the assessment and leaving
   no way to run the scanners without reserving a session or querying the
   model. The shared helper `_recon_choice_menu` (`penx_app/cli/app.py`)
   now owns the MODE phase, the active/passive choice and the passive
   recon fallback, returning `(raw_scan, passive_used)`; both callers own
   interruption and tool-failure handling. The full scan flow keeps its
   prior semantics: sessions are created only after recon completes,
   interruptions/failures return the same `ScanOutcome` acknowledgement
   states, and a picker passive choice still reaches `analyse_target` as
   `passive_only=True`. A new main-menu step, "Run Recon Tools (no
   assessment)", runs the picker with no session reservation, no storage
   writes, no model query and no model-credential preflight. The new
   contract suite `tests/test_recon_menu.py` (13 tests) pins picker
   passthrough, passive switching, forced-passive picker skip,
   interruption propagation, passive flag flow into the model call, every
   no-session/no-model boundary of the recon-only step, and main-menu
   routing for the new step. Verified locally: 103/103 offline suites,
   Ruff and mypy clean on the changed files,
   `scripts/import_inventory.py --check` clean, benchmark threshold gate
   passed with no violations.

## Post-merge implementation update (16 October 2026)

PR #171 is merged in `main`. Its model transport snapshot, typed repository
readers, scanner cancellation regression suites, `METATRON_*` compatibility,
in-memory provenance and standalone recon menu are no longer pending review.
Older checkpoint-specific "in progress" descriptions above document the work
as originally done; they are not outstanding pull requests.

Follow-up on `refactor/remaining-contracts-20261016`:

- Adapter-origin evidence anchors are serialized in size-limited scan-metadata
  version 2, retaining legacy version-1 reads. Records are source-checked at
  serialization and schema-validated on restore. **Restored records are
  historical provenance claims, not fresh source verification** because
  raw adapter text is intentionally not reconstructed from metadata.
- The standalone recon picker no longer reads session history or requires a
  functioning assessment DB; scope/consent is still enforced by the picker.
- Model pipeline source-result formatters are injectible, with offline
  contract tests. Broader source transport injection remains open.

The full refactor is **not signed off**. Remaining engineering/acceptance
gates: independently validated scanner provenance after persistence (against
the original scanner evidence); broader external-source transport injection;
audited legacy facade deprecation without breaking consumers; further CLI
presentation separation; wider Ruff/mypy coverage; production-shaped
SQLite/MariaDB backup-restore tests; actual scanner process-tree field tests;
real per-user Windows/Npcap/UAC/installer rollback; and manual long-PDF
inspection. Green CI is necessary but cannot replace physical/field tests.
No destructive or automatic customer-data migrations are authorized.

### CI gate expansion after the provenance follow-up (16 October 2026)

The Linux CI Ruff F401 unused-import gate and mypy contract gate now include
four additional extracted modules: `storage/db_backend.py`,
`storage/evaluation_repository.py`, `cli/scanner_menu.py`, and
`cli/db_display.py`. This enforces import and type hygiene at the storage
backend and terminal presentation boundaries without introducing an
unreviewed repository-wide formatting rewrite. `db_backend.SCHEMA` remains
an explicitly exported public compatibility symbol.

The remaining whole-tree type/lint expansion, audited legacy facade removal
and manual scanner / Windows hardware / database recovery acceptance are
**not** signed off by this change.

### Further Pk08/Pk09 isolation (16 October 2026)

- The scanner choice and preset policy is now a pure application function
  (`application/scanner_selection.py`), independent of CLI output, DB or
  networking. The existing terminal layer still owns the back-navigation,
  active-scan consent and dispatch; contract tests cover all twelve menu
  options, bounded presets and mixed passive-choice rejection.
- The model tool dispatcher accepts explicit scanner and search client
  callbacks, preserving existing allowed-target validation and default
  implementations. Tests confirm the injected clients flow through the
  authorization dispatcher unmodified.
- Full CLI decomposition and source-client lifecycle independence remain
  incremental follow-ups, not claimed as complete solely by the new ports.

### Persisted anchor integrity follow-up

A persisted `EvidenceRecord` is rejected when its quote character length
does not equal `raw_end - raw_start`, even when both offsets are individually
within range. This catches corrupted or manipulated source-span claims at
deserialization. A stored quote is still historical evidence metadata rather
than independently verified live scanner output.

## Invariants and review rules

- Never enlarge model-scanner allowlists, CIDR scope, active-tool consent or
  passive scanning behavior as an incidental refactor.
- Raw scanner and AI text are untrusted; remote text cannot invent trusted
  adapter status or confirmed exploitability.
- Save completed assessments atomically, preserve failure evidence before
  cleanup, and export only after commit. A saved assessment survives report
  generation failures.
- Keep SQLite as the default, MariaDB upgrades explicit, and user data out
  of commits, fixtures and release bundles.
- Use small, independently reviewable PRs with a documented rollback path.
  Changes to storage require MariaDB tests; changes to import/bootstrap or
  releases require portable Windows build checks.

**Completion criterion:** Only claim the original plan complete when every
remaining acceptance item and manual/automated verification gate above has
independent evidence, including all twelve scanner modes, both database
backends, preserved old sessions and all report formats.


### Independent checkpoint-review follow-up

- Multi-format reports use **atomic individual file writes**, with a persisted
  `in_progress` manifest to detect an interrupted batch; this is **not**
  atomic visibility of HTML/PDF as a pair. Re-running the publication repairs
  interrupted batches. Ordinary renderer/IO errors are marked `partial`,
  while a simulated hard crash retains `in_progress`. An actual power-loss
  durability test and automatic startup recovery are still outside CI evidence.
- Deleting a session's HTML/PDF reports also removes the corresponding hidden
  publication manifest, after validating all file types. A file-system error
  during a sequence of deletions is not a multi-file transactional rollback.
- CI, release builds and Windows source installations now use the hash-locked
  **runtime** requirements for their actual dependency environment. Python
  3.10–3.12 compatibility workflows also install the lock and exercise package
  entrypoints. Hash verification across all platforms must pass before
  considering the matrix verified.
- The separate `requirements-build.txt` PyInstaller tooling is **not**
  transitive-hash locked, so a fully reproducible Windows **build toolchain**
  remains follow-up work. Tagged release artifacts still require physical
  Windows/UAC/Npcap and installer rollback sign-off.


### Independent source transport seams (16 October 2026)

- `intelligence/source_verification.py` accepts explicit per-call HTTP GET clients for
  NVD and CISA lookups and injectable NVD, applicability and KEV provider functions
  at the finding verification boundary. Test transports do not read or contaminate
  the process-wide production CVE/KEV caches; the existing public default API
  and source-verification semantics are preserved.
- `intelligence/search.py` accepts injectable DDGS search factories, HTML GET
  clients and per-dispatch search/page clients, without widening model-requested
  tool permissions or making external requests in offline fixtures.
- `tests/test_source_transport_injection.py` exercises isolated cache behavior,
  timeouts, never sending raw scan data to the NVD lookup, source failure
  contracts, search dispatch and HTML normalization. This covers part of Pk08;
  it is **not** end-to-end injection of every third-party advisory provider and
  does not close the real Windows/network/manual acceptance gates.


### Follow-up contracts: Pk02, Pk04, Pk10, Pk12 (16 October 2026)

- The scanner picker now preserves `duration_seconds`, `exit_code` and
  `diagnostics` when adapting typed scanner results back to the string-compatible
  formatter contract. The 508 resource-limit short-circuit uses the registered
  scanner identity and an explicit skipped diagnostic. Nmap's subprocess exit
  metadata is retained through its scanner adapter. Offline tests pin all
  three boundaries without scanning any target.
- `test_full_legacy_settings_matrix.py` checks every presently supported
  typed `METATRON_*` fallback against its `PENX_*` override, including empty
  new credentials and no writes to read-only-style installation folders.
  This is configuration logic coverage, not a real read-only EXE test.
- `test_large_synthetic_reports.py` exercises the HTML/PDF/JSON/SARIF
  projections on 120 synthetic findings and verifies rejected findings are
  excluded. It does not substitute for human PDF pagination or real-world
  report review.
- Ruff and mypy include the source verification boundary in Linux CI.
  Neither tool's success proves repository-wide type/lint cleanliness.
- Field-only checks in `REFACTOR_ACCEPTANCE.md` remain unsigned:
  real scanner cancellation and consent, restore rehearsal using authorized
  sanitized backups, Windows UAC/Npcap/installer rollback, and manual PDF review.

### Recoverable publication warnings (Pk10)

The View History dialog now surfaces a validated `in_progress` or `partial`
report publication manifest and directs operators to manually regenerate the
HTML/PDF pair from the committed session. This is a read-only, session-scoped
check; it rejects inconsistent metadata and symlinks and never deletes,
regenerates, or migrates customer data automatically. Offline tests cover
crashed/partial/complete states and no-write UI behavior. An actual power-loss
rehearsal remains an independent field acceptance gate.


### Provider adapter call-site injection (Pk08, 16 October 2026)

- WordPress GitHub Advisory research accepts a call-local HTTP GET transport,
  retaining exact slug allowlists, bounded per-page limits, no redirects,
  conservative version-range statuses and non-leaking failure handling.
- Red Hat/Ubuntu advisory JSON has a shared bounded request helper and
  optional direct-test transports. Production memoized lookups still work
  when no test client is supplied; injected responses never use or populate
  those process-wide caches. Vendor guidance also accepts per-call loaders
  and treats provider connection/timeout failures as **unavailable**, never
  as evidence of a fixed or vulnerable target.
- Shodan IP research accepts a call-local DNS resolver and an endpoint resolver.
  Every returned address is revalidated as public IPv4 at the external
  service boundary even when the injected resolver is incorrect. Disabled
  lookup performs neither DNS nor HTTP requests. Shodan remains a
  historical observation service, not live vulnerability verification.
- Offline regression tests assert no actual DNS/HTTP calls and exercise
  malformed replies, timeouts, cache isolation, authorization boundaries,
  non-disclosure of mock secrets and private/reserved IP rejection.
  The three provider modules are included in the Ruff F401 CI gate.
- **Not equivalent to finished Pk08:** Higher-level discovery orchestration,
  full retry/cancellation lifecycle contracts and real source network
  behavior remain separate acceptance requirements.


### EPSS/CVSS priority failure contracts (Pk08, 16 October 2026)

- FIRST EPSS HTTP GET is now call-local/injectible with a fixed provider URL,
  no redirects, bounded CVE list, fixed request deadlines and conservative
  unavailable/incomplete warnings for malformed roots and entries.
- Malformed NVD CVSS metadata arrays/scalars no longer crash priority
  extraction or invent a score. The optional priority source clients are
  explicitly injected and rate/connection failures produce **unknown**,
  not a fabricated zero risk/exploitation status. Injected scores must be
  finite, numeric and in 0..1 before influencing candidate ordering.
- Offline `test_priority_provider_contracts.py` covers malformed CVSS/EPSS,
  non-finite metrics, actual client bypass, disabled/invalid data, source
  failures and no secret leakage. Ruff F401 includes `cve_priority.py`.
- This is another research-data resilience and injection boundary; it does not
  close the outstanding real Windows scanner, database restore, installer,
  GUI or physical field-acceptance gates.


### Cooperative subprocess cancellation (Pk04, 16 October 2026)

- `scanners.process_runner.run_tool(..., cancel_event=threading.Event())`
  now supports an **optional, caller-owned** cancellation signal in both
  quiet and live streaming modes. A pre-set signal prevents a process from
  starting. A signal raised during a run terminates the scanner process
  group/descendants through the existing timeout cleanup path. The result is
  `PARTIAL` with `evidence=False`, a bounded cancellation diagnostic and
  no untrusted scanner text represented as completed evidence.
- Quiet execution checks cancellation at bounded intervals while retaining
  existing timeout, pipe draining and process tree exception handling;
  live execution checks it before each next bounded output chunk.
- Offline tests use only local, synthetic Python subprocess/grandchild trees
  and exercise pre-cancellation, both streaming modes, cleanup/no-orphan
  markers and unchanged normal success. Ruff F401 covers the runner module.
- **This is a process-runner seam, not full Pk04 field sign-off**: individual
  scanner adapters and interactive menu do not yet wire a UI cancellation
  token end-to-end. Real Nmap/Nikto/Nuclei/ffuf/Katana/Subfinder process-tree
  cancellation needs authorized Windows field testing.


### Scanner sequence cancellation (Pk04/Pk05, 16 October 2026)

- The application-layer `run_selected` and `run_selected_structured`
  dispatcher accepts an optional caller-owned `threading.Event`. Once set,
  every remaining selected adapter receives a trusted `PARTIAL`/
  `evidence=False` outcome with its registered ID. No queued scanner is run.
  Previous genuine evidence and explicit coverage remain intact.
- Active-scanner consent and passive-only policy checks occur before any
  cancellation shortcut and may not be bypassed by pre-cancelling.
- Pure offline tests pin pre-cancel, cancel-after-first-adapter, no-token
  defaults, preserved provenance and both authorization gates.
- The dispatcher and separately merged `process_runner.run_tool(cancel_event=...)`
  are **opt-in components**, not yet wired by every native wrapper or the
  terminal UI. End-to-end Windows/hardware acceptance remains outstanding.


### Native adapter cancellation propagation (Pk04/Pk05, 16 October 2026)

- `run_selected` now forwards its opt-in `cancel_event` only to runner
  callables explicitly declaring that named parameter. Unknown legacy
  functions continue receiving exactly `runner(target)`. A TypeError inside
  a scanner is never retried, preventing an accidental duplicate scan.
- Nmap, WhatWeb, Nikto, Nuclei, ProjectDiscovery httpx, ffuf, Subfinder and
  Katana wrappers accept `cancel_event` and pass it to the common subprocess
  runner. A pre-set token bypasses discovery and subprocess creation.
  WhatWeb does not make fallback HTTP requests after cancellation.
  Legacy calls without a token retain their previous argument signatures.
- Offline tests assert identity preservation end-to-end from the application
  dispatcher to the native process client, normal legacy compatibility,
  no double-dispatch, eight pre-cancelled wrappers and no WhatWeb fallback.
- **Still not full real-world field approval:** Python WHOIS, DNS, HTTP-header
  and TLS adapters use request-level deadlines rather than this token.
  Interactive CLI cancellation and real installed-scanner process-tree tests
  on an authorized Windows target remain independent acceptance requirements.

### Interactive scanner Ctrl+C cancellation follow-up (16 October 2026)

The terminal scanner-selection boundary now installs a temporary SIGINT
handler while selected native scanners run. First Ctrl+C sets a *fresh*
caller-owned cancellation event propagated through the existing
`run_selected_structured` dispatcher to opt-in scanner adapters and the
bounded process runner. A second Ctrl+C still raises KeyboardInterrupt,
allowing emergency process-tree cleanup and existing menu interruption
handling. The handler is restored on return or error, and is never installed
from a non-main thread.

After cancellation, the scanner-selection CLI returns **no assessment** even
if an earlier selected adapter produced evidence; no formatter/model step
can silently treat a cancelled scan as complete. The selected-scan dispatcher
still retains trustworthy previous evidence in its structured result for
programmatic callers, and skips queued adapters with PARTIAL status.
User consent and target-scope validation are not bypassed. Synthetic
`tests/test_cli_scanner_cancel.py` checks signal lifecycle, a two-tool
cancelled scan, unchanged successful formatting, non-main-thread fallback,
and consent refusal.

**Remaining field acceptance:** Genuine Ctrl+C process-tree termination on
authorized Windows targets, Npcap/UAC/installed-console behavior, and
adapters using bounded blocking Python HTTP/DNS/WHOIS/TLS requests rather
than native subprocess cancellation. This PR does not sign off Pk04/Pk05.

### CLI/selection quality-gate extension (16 October 2026)

The Linux CI Ruff F401 and mypy checks now include four more maintained,
testable modules: `application/scanner_selection.py`,
`cli/scanner_cancellation.py`, `cli/cli_navigation.py` and
`scanners/registry.py`. A regression test prevents accidental removal
of these source paths from either quality gate. This improves typed
coverage at the interactive scan boundary without claiming full tree
mypy cleanliness or end-to-end physical Windows sign-off.
