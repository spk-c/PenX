# PenX Architecture Plan — Phase 0 Audit

- Date: 2026-10-21
- Base: `main` @ `7a32d19` ("fix: restore green CI and retire completed release workflow")
- Method: static audit of `src/penx_app`, `tests`, `.github/workflows`, and docs;
  full offline baseline run.
- Companion docs: `docs/ROADMAP.md` (phase plan), `docs/ROADMAP_PROGRESS.md`
  (progress tracker with run records).

## 1. Baseline and CI state

- Test suite: 197 offline suites auto-discovered by `offline_tests.py`
  (unittest, one subprocess per suite, no network, mocked `input()` and
  subprocesses).
- Historical breakage: at `ccafc10`, two suites failed because
  `docs/RELEASE_0.4.9_NOTES.md` had been deleted in `0f21abd` while
  `test_github_repository_configuration.py` and `test_release_v049_contracts.py`
  still required it. Upstream `7a32d19` retired the one-shot v0.4.9 release
  workflow, replaced the contracts with `test_release_pipeline_contracts.py`,
  and repointed the github-configuration suite at `docs/PACKAGING.md` and
  `docs/MAINTENANCE_STATUS.md`. Baseline result at `7a32d19`: see
  `docs/ROADMAP_PROGRESS.md`.
- CI (`.github/workflows/ci.yml`): offline tests on `windows-latest` +
  `ubuntu-latest`; ruff fatal gates (`E9`, `F63`, `F7`, `F82`) plus a staged
  `F401` file list; mypy on a growing module list plus full-tree ruff/mypy
  gates (Linux); PyInstaller EXE and Inno Setup installer smoke; synthetic
  refactor benchmark thresholds (`scripts/refactor_benchmarks.py`); CVE fixture
  quality report. Separate workflows: publish, security (CodeQL/Gitleaks),
  packaging, issue triage, field-acceptance evidence.

## 2. Current state: scanner orchestration (Phase 1 baseline)

Execution path today:

1. `cli/app.py::_execute_scan` — target prompt, LLM auth preflight, recon
   choice menu, consent handling, coverage checks.
2. `application/scanner_selection.py::resolve_scanner_selection` — pure policy.
   Presets `a` = keys 1–5, `n` = 1–6, `x` = all keys except `e`; `0` =
   passive-only; unknown or mixed choices return `None` (no launch).
3. `application/scanner_execution.py::run_selected` /
   `run_selected_structured` — sequential loop over chosen adapters with
   per-adapter `try/except` error isolation; consent enforced before the first
   adapter; passive-only rejects active adapters; HTTP 508 overload guard skips
   remaining active scanners; cooperative cancellation via `threading.Event`;
   bounded evidence anchor attached per adapter via `capture_evidence`
   (kind `adapter_output`, parser version 1, ≤ 2000 bytes).
4. Adapters: `scanners/tools.py` (nmap, whois, whatweb, http headers, dns,
   nikto, nuclei, httpx, ffuf), `scanners/native_web_scanners.py`,
   `scanners/passive_recon.py`, `scanners/endpoint_inventory.py`.
5. `application/assessment_service.py::run_assessment` — LLM review,
   persistence, reports.

Existing building blocks (keep, do not rewrite):

- `scanners/registry.py` — stable scanner IDs (`1`–`9`, `e`, `s`, `c`, `d`);
  consent keys: nuclei, ffuf, endpoint_mapping, katana; resource-sensitive:
  nikto, nuclei, httpx, ffuf, endpoint_mapping, katana.
- `scanners/process_runner.py` — subprocess with process group
  (`CREATE_NEW_PROCESS_GROUP` / `taskkill /T /F` on Windows, `killpg` on
  POSIX), bounded 1 MiB capture, bounded drain, bounded timeout.
- `scanners/tools.py::_scanner_timeout` — per-scanner `PENX_<NAME>_TIMEOUT`
  env var, clamped to 30–900 s.
- `scanners/scanner_runtime.py` — `find_nmap`, `find_runtime` (ruby, perl),
  `npcap_present`; availability detection exists but only at adapter level.
- `domain/scan_models.py` — `ScanRequest`, `ScannerResult` (status, evidence,
  duration, exit_code, diagnostics, evidence_records), `ScanResult` with
  metadata v1/v2 and `coverage()`; `ScannerOutput`/`ReconText`
  str-subclass compatibility boundary.
- `domain/evidence.py` — `EvidenceRecord`, `capture_evidence`,
  `revalidate_persisted_evidence`.

Gaps against Phase 1 acceptance:

1. No first-class validated scan-plan object. Selection maps menu keys to ID
   tuples ad hoc; scope, consent, and budget are not a single validated
   artifact.
2. No DAG and no controlled parallelism. Execution is strictly sequential;
   there is no `max_parallelism` or rate limit.
3. No global scan budget (only per-scanner timeouts).
4. No preflight/dry-run surface: availability, versions, scope, consent,
   budget, and planned order are not obtainable without starting a scan.
5. Version detection is split: presence checks in
   `scanners/scanner_runtime.py` vs. banner parsing in
   `reporting/finding_trace.py` — no unified availability + version view for
   the orchestrator.
6. Runtime diagnostics are per-adapter fields, not a bounded structured event
   stream.

## 3. Current state: evidence and scan comparison (Phase 2)

Implemented (PR #94 baseline `ad21266` plus follow-ups):

- `domain/evidence.py` — bounded exact raw slices (≤ 2000 bytes) with quote
  length validation, in-memory 12-hex checksum, and evidence status.
- `domain/scan_models.py::ScanResult.metadata` — persisted scanner metadata
  v2 carrying evidence records.
- `reporting/finding_trace.py` — per-finding provenance: scanner, observed
  banner version, exact raw excerpt, evidence status, evidence reference;
  conservative missing-finding states (no auto-resolve).
- `application/scan_trends.py` — conservative comparison with states
  `new` / `still_present` / `severity_changed` / `not_observed` /
  `not_checked` / `scan_failed` / `resolved`; matching by identity + severity
  bucket + reworded recommendation pairing; coverage-gated port comparison;
  Shodan InternetDB diff; JSON/HTML/PDF diff export.
- `reporting/machine_reports.py` — `penx-assessment-v1` JSON and SARIF 2.1.0
  with provenance properties, redaction, atomic `publish_unique`.

Open items against Phase 2 acceptance:

1. No content-stable finding fingerprint across sessions (current matching is
   name/port/service key + severity bucket + recommendation topics).
2. Raw output is stored as bounded quote + offset anchors, not as hashed
   artifacts; Phase 2 asks for optional SHA-256 artifact hashes plus validator
   references — requires bounded raw-artifact storage (additive migration).
3. Comparisons do not explicitly note differing scan profiles/selections
   (implicit today through coverage states).
4. Diff reports do not yet surface both sessions' scanner coverage and
   profile/configuration metadata.

## 4. Current state: reporting, CLI, configuration, AI

- Headless surface today (`bootstrap.py`): `--version`, `--check`,
  `--setup-status`, `--setup`, `--setup-native`, `--llm-setup`,
  `--check-update`, `--update`, `--export-session <ID> --format json|sarif
  [--redact]`. No headless scan command.
- Configuration: `.env` knobs (`PENX_LLM_URL`, `PENX_MODEL`, `PENX_TIMEOUT`,
  `PENX_VERIFY_SOURCES`, `PENX_CVE_*`, `PENX_DB_ENGINE`, per-scanner
  `PENX_*_TIMEOUT`). No typed per-scanner config schema, no profile-scoped
  settings.
- UX: advanced-first menu flow (`cli/app.py::_recon_choice_menu`); no guided
  mode.
- AI: OpenAI-compatible local endpoint, AI tool protocol
  (`analysis/ai_tool_protocol.py`), schema-validated structured output,
  bounded prompts, hallucination corrections (`domain/corrections.py`).

## 5. Technical debt and coupling findings

1. Sequential execution only; no hard deadline for the whole scan (cooperative
   cancellation only).
2. Availability/version knowledge is split between
   `scanners/scanner_runtime.py` (presence) and `reporting/finding_trace.py`
   (banner parsing) — not reusable by the orchestrator.
3. Legacy compatibility boundary: `ScannerOutput`/`ReconText` str-subclasses
   exist until adapters are fully typed (guarded by
   `test_scanner_result_boundary.py`).
4. `application/scan_trends.py` imports storage helpers (`get_session`) —
   acceptable per layering (application may use storage); `domain/` stays
   pure (`test_architecture_boundaries.py`).
5. Ruff gates are minimal (`E9`, `F63`, `F7`, `F82`) plus a staged `F401`
   file list; mypy gates cover a growing module list — keep green, do not
   broaden gates without a dedicated effort.
6. `tests/mariadb_integration.py` is intentionally not auto-run (offline
   suites only in CI).

## 6. Quality goals (measurable)

1. All offline suites green before each phase merge (baseline 197 suites; new
   packages add suites).
2. `domain/` stays pure — no imports from `cli`, `storage`, `reporting`,
   `requests`, `subprocess`, `sqlite3`, `urllib.request` (enforced by
   `test_architecture_boundaries.py`).
3. No unbounded scanner capture: the 1 MiB cap in `process_runner.py` is
   preserved.
4. New orchestration logic is offline-testable with mock adapters (no
   network, no real subprocesses).
5. No new ruff/mypy violations; full-tree gates stay green.
6. Backward compatibility: presets `a`/`n`/`x` and passive-only unchanged;
   storage changes additive via migrations; existing CLI invocations keep
   working.
7. No invented test results: every claim in `docs/ROADMAP_PROGRESS.md` cites
   an actual run.

## 7. Phase 1 implementation packages (ordered, separable)

All packages: feature branch `feature/phase1-orchestration` from current
`main`; small commits per package; offline regression tests per package;
acceptance mapping to brief §1.4.

### P1-1 — `ScanPlan` domain type

- New `src/penx_app/domain/scan_plan.py`: frozen, validated plan — profile
  id/version, target, scanner IDs (validated against `registry`), per-scanner
  timeouts (clamped 30–900 s), `max_parallelism` (≥ 1), optional rate limit,
  optional global budget.
- `to_request()` produces today's `ScanRequest` 1:1 (compatibility).
- Domain-pure; explicit validation errors; no shell strings.
- Tests: `tests/test_scan_plan.py` — valid/invalid plans, unknown scanner
  IDs, timeout clamping, preset equivalence with
  `resolve_scanner_selection`.
- Acceptance: "validated scan plans before execution" — the plan is the only
  entry for the executor.

### P1-2 — Planner + controlled executor

- New `application/scan_planner.py`: plan → execution schedule; small DAG
  (initial dependency set empty → registry order); `max_parallelism` default
  1; deterministic aggregation keyed by scanner ID in stable order; per-node
  timeout plus global budget; rate-limit hook.
- Extend `scanner_execution.run_selected` (or add `run_plan`) — reuse the
  existing consent check, per-adapter error isolation, `cancel_event`,
  process-tree teardown, and evidence anchoring. Default sequential mode must
  change behavior zero (existing tests stay green).
- Tests: offline mock adapters — determinism at parallelism 1/2/3, error
  isolation, cancellation leaves no orphans (process-group teardown path),
  budget cutoff, passive-only stays passive, consent gating.
- Acceptance: brief §1.4 items on failure isolation, cancellation,
  reproducibility, offline testability.

### P1-3 — Profile registry v1

- New `application/scan_profiles.py`: versioned profiles `passive`,
  `standard`, `web_audit`, `full_assessment`, `custom`; each with id,
  version, scanner IDs, default timeouts/parallelism, and consent
  requirements. Built-ins immutable; `custom` = explicit IDs + options.
- Preset compatibility: `a`/`n`/`x` must produce exactly the same ID sets as
  today (tests compare against `resolve_scanner_selection` output).
- Profiles describe allowlisted fields only (typed options land in Phase 4).
- Tests: offline unit tests.
- Acceptance: brief §1.2 profile table + backward compatibility.

### P1-4 — Preflight + dry-run

- Extend `scanners/scanner_runtime.py` with `scanner_availability(scanner_id)`:
  presence + best-effort version (reusing `finding_trace` banner parsing and
  runtime probes) + missing dependencies (ruby/perl/npCap per scanner).
- New headless dispatch `penx preflight --target <host> [--profile <name>]`:
  prints scope, selected scanners, availability + versions, budgets, consent
  requirements, missing dependencies, and planned order. No network, no
  adapters.
- Tests: offline (mocked `shutil.which` / version probes); assert no adapter
  invocation.
- Acceptance: brief §1.3.

### P1-5 — Structured runtime diagnostics

- Bounded per-scanner events (start, finish, status, duration, exit code)
  aggregated into `ScanResult.metadata` as an additive versioned field;
  progress via the existing `emit` hook.
- Tests: offline mock adapters; assert metadata structure, bounded size,
  stable ordering.
- Acceptance: brief §1 "structured runtime diagnostics" and "traceable
  progress information".

Package dependency: P1-1 → {P1-2, P1-3} → P1-4 (needs planner order +
profiles) → P1-5 (needs executor).

## 8. Risks and mitigations

- Parallel execution changes timing/order: deterministic aggregation keyed by
  scanner ID; default parallelism 1 keeps today's behavior exactly.
- Cancellation under parallelism: per-node process-group teardown unchanged;
  `cancel_event` semantics preserved.
- New profile surface could bypass scope/consent: profiles reference only
  registry IDs; consent still enforced in the executor before the first
  active adapter; passive profiles cannot select active IDs (validated in
  P1-1).
- Storage growth from diagnostics: bounded metadata (fixed-size per-scanner
  records), versioned.
- Testability: all new logic is pure/application-level with mock adapters —
  no live targets (standard #12).

## 9. Next steps

1. Phase 0 completes with this document, `docs/ROADMAP.md`,
   `docs/ROADMAP_PROGRESS.md`, and a recorded green baseline.
2. Start Phase 1 on branch `feature/phase1-orchestration`, package P1-1
   first.
