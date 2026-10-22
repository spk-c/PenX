# PenX Roadmap Progress

## Phase 6 completion — 2026-10-22

- Added explicit `penx review-scan` for bounded draft triage of existing headless
  collection reports. Core collection/profile/guidance paths still require no AI.
- Added schema, source identity and exact evidence citation validation; unknown
  fields, new scanner selections and confirmed/resolved states are rejected.
- Added loopback-only transport with no environment proxies, redirects, model
  discovery, retries or tool capability. No action dispatcher is present.
- Separate drafts retain the source file SHA-256 and unverified state; original
  findings, coverage, severity and CI policy are never rewritten.
- Added 12 offline local-AI/input/transport/publication boundary tests.
- Verification: **all 212 offline suites passed**, exit 0. Full-tree fatal Ruff,
  application F401 and Linux-platform mypy passed (118 source files).
- No live target, model endpoint or authorized-scan CI job was invoked. Actual
  model/backend behavior and Windows field acceptance remain outside these
  offline claims. Bounds and limitations are documented in `LOCAL_REVIEW.md`.
- Phases 0–6 are now implemented and regression-tested on the continuation
  branch. Release packaging and merging this branch are separate operations.

## Phase 5 completion — 2026-10-22

- Added `penx guided` and main-menu [g], with goal-based profiles and a
  plain-language explanation for every registered scanner.
- Added exact-host scope display, permission/active-consent questions, local
  preflight, explicit incomplete-coverage acceptance and final start confirmation.
  Back/decline/EOF paths never dispatch from the preview.
- Explained severity, confidence, evidence and incomplete coverage before
  collection. Confirmed runs reuse the existing headless path; advanced flows
  remain available. Guided collection creates no AI/DB assessment session.
- Added 12 offline wizard/guidance/dispatch tests.
- Verification: **all 211 offline suites passed**, exit 0; full-tree fatal Ruff,
  application F401 and Linux-platform mypy passed (115 source files).
- Usage and beginner scope limits: `GUIDED_MODE.md`.
- Next: Phase 6 optional bounded local-AI review, preserving non-AI operation
  and preventing model-originated execution or scope expansion.

## Phase 4 completion — 2026-10-22

- Added strict typed per-scanner timeouts, Nmap ports, Nuclei severity subsets
  and non-increasing native scanner request rates. Fixed argument lists retain
  safety flags and target scope; arbitrary flags/paths/secrets are rejected.
- Added bounded versioned profile validation, builtin/custom export and explicit
  headless profile import. Files contain no target or transferable authorization.
- Bound options within worker contexts; persisted allowlisted metadata v3
  snapshots and exposed configuration differences in comparisons.
- Fixed node timeout signaling, occupied-worker accounting, global cancellation
  after final dispatch, and budget/cancellation checks after dispatch waits.
- Added 12 offline configuration/profile/deadline acceptance tests. Verified
  actual adapter argument forwarding through mocked process execution.
- Verification: **all 210 offline suites passed**, exit 0; the final menu-guard
  adjustment was additionally checked by the 15 executor tests, all passed.
  Ruff full-tree/F401 and Linux-platform mypy passed (113 source files).
- Usage, caps and cooperative-I/O limitations: `SCANNER_CONFIGURATION.md`.
- Next: Phase 5 guided beginner mode, profile recommendations and explanations.

## Phase 3 completion — 2026-10-22

- Added authorized headless `penx scan`, using existing profiles/planner and
  explicit consent. No model, DB session or interactive prompt is required.
- Added distinct collection JSON, shared SARIF formatting with stable partial
  fingerprints, severity policy and documented exit codes 0 through 5.
- Added standalone saved-assessment/collection schemas, validated against real
  export fixtures. Headless findings currently rate explicit Nuclei matches;
  remaining adapters provide coverage, never invented vulnerability verdicts.
- Added optional manual-only authorized-scan workflow, quoted input handling,
  optional SARIF upload and preserved policy outcome. It was not dispatched.
- Added 12 offline acceptance tests in `test_headless_scan.py`.
- Verification: `.venv/Scripts/python.exe offline_tests.py`: **all 209 suites
  passed**, exit 0. Full-tree fatal Ruff, application F401 and Linux-platform
  mypy gates passed (110 source files). No live target was scanned.
- Usage and limitations: `HEADLESS_SCANS.md`. Passive provider completeness
  remains partial; unsupported planner overrides are rejected before collection.
- Next: Phase 4 typed per-scanner configuration and safe custom profiles.

## Phase 2 completion — 2026-10-22

- Phase 1 was merged in PR #100 (`43d0918`); its historical review entries
  below are retained as run records. The roadmap overview now reflects this.
- Stable versioned finding fingerprints now drive exact comparison matching
  and appear in JSON/SARIF exports, independently of storage IDs and severity.
- Optional `PENX_RAW_ARTIFACT_DIR` retention writes bounded exact UTF-8 adapter
  captures. Additive metadata v3 references carry full SHA-256, size and a
  validator ID. Separate validation checks file integrity and evidence anchors;
  reports explicitly distinguish a saved reference from revalidation.
- Diff JSON/text/HTML/PDF include both sessions' coverage and recorded plan
  configuration, with explicit differing-selection/profile and legacy warnings.
- Added `tests/test_phase2_traceability.py`: 10 offline acceptance tests.
- Verification: `.venv/Scripts/python.exe offline_tests.py` outside the Windows
  sandbox: **all 208 suites passed**, exit 0. In the sandbox, four existing
  process-tree suites cannot terminate descendants; the unrestricted run passes.
- Ruff fatal full-tree and F401 application gates: passed. Full-tree mypy with
  CI import flags and `--platform linux`: passed, 109 source files.
- Usage, retention bounds and integrity limitations: `EVIDENCE_TRACEABILITY.md`.
- Next: Phase 3 headless scanning, exit-code policy, standalone schemas and
  optional CI SARIF upload.

Continuous tracker for the phase program defined in `roadmap.md` (brief) and
`docs/ROADMAP.md` (phase plan). Each entry records: phase, affected files,
implemented change, tests with actual results, open risks, commit/PR link,
and the next concrete step.

Status values: `NOT STARTED` / `IN PROGRESS` / `IMPLEMENTED` / `TESTED` /
`READY FOR REVIEW` / `COMPLETE` / `BLOCKED`.

## Phase 0 — Repository audit and development baseline

### P0-1 — Baseline test run (initial) — COMPLETE

- Date: 2026-10-21, base `ccafc10`, branch `feature/phase0-repo-audit`.
- Command: `python offline_tests.py --keep-going`.
- Result: 197 suites; 2 failures:
  - `tests/test_github_repository_configuration.py` — `FileNotFoundError:
    docs/RELEASE_0.4.9_NOTES.md`
  - `tests/test_release_v049_contracts.py` — same missing file.
- Root cause: commit `0f21abd` ("docs: remove obsolete public repository
  documents") deleted the notes file while both suites still pinned it.
- Status: COMPLETE (failure documented, root cause identified).

### P0-2 — Green baseline at current main — COMPLETE

- Upstream `7a32d19` ("fix: restore green CI and retire completed release
  workflow") retired the one-shot v0.4.9 release workflow, replaced
  `test_release_v049_contracts.py` with `test_release_pipeline_contracts.py`,
  and repointed the github-configuration suite at `docs/PACKAGING.md` and
  `docs/MAINTENANCE_STATUS.md`.
- Date: 2026-10-21, base `7a32d19` (main).
- Command: `python offline_tests.py --keep-going`.
- Result: `[OK] All 197 PenX offline test suites passed.` (exit code 0).
- Status: COMPLETE.

### P0-3 — Audit and phase documents — COMPLETE

- Files: `docs/ROADMAP.md`, `docs/ARCHITECTURE_PLAN.md`,
  `docs/ROADMAP_PROGRESS.md` (this file).
- Change: documented current state (orchestration, evidence/comparison,
  reporting/CLI/configuration/AI), technical-debt inventory, measurable
  quality goals, and Phase 1 packages P1-1 … P1-5 with acceptance mapping
  and test strategy (see `docs/ARCHITECTURE_PLAN.md` §7).
- Tests: documentation only, no behavior change; baseline run above is
  unchanged and green.
- Open risks: none for Phase 0.
- Commit/PR: see branch `feature/phase0-repo-audit`.
- Next step: Phase 1, package P1-1 (`ScanPlan` domain type) on a new feature
  branch `feature/phase1-orchestration` from current `main`.

## Phase 1 — Scanner orchestration and flexible scan profiles

Branch: `feature/phase1-orchestration`; authoritative plan in `plan.md`
(commit `3d553fa`). All packages use mock adapters only (offline). The
existing sequential path is untouched: `run_plan` with
`max_parallelism == 1` and no budget/dispatch delegates to
`run_selected_structured` unchanged.

### P1-1 — ScanPlan domain contract — READY FOR REVIEW

- Commit: `b03a62d` — `feat(domain): add versioned ScanPlan contract with budgets and consent rules`.
- Files: `src/penx_app/domain/scan_plan.py`, `tests/test_scan_plan.py`.
- Change: frozen `ScanPlan` dataclass with rules R1–R10,
  `validate_plan` / `assert_valid_plan`, `PlanValidationError`;
  per-scanner timeouts 30–900 s, global budget ≥ 30 s, dispatch
  interval ≤ 60 s, consent keys `7`/`9`/`e`/`c`, passive plans may not
  select scanners.
- Tests: all R1–R10 rule cases plus boundary values — 16/16 pass.

### P1-2 — Plan executor with bounded parallelism — READY FOR REVIEW

- Commit: `4095f20` — `feat(application): add plan-based scan planner and bounded parallel executor`.
- Files: `src/penx_app/application/scan_planner.py`,
  `src/penx_app/application/scanner_execution.py`,
  `tests/test_plan_executor.py`.
- Change: `run_plan` validates the plan before dispatch; parallelism > 1,
  budgets, and dispatch intervals run through a bounded
  `ThreadPoolExecutor` scheduler (per-node timeouts, cooperative
  cancellation, 508 overload guard, plan-order row output).
  `scanner_execution.py` refactored to shared helpers
  (`_cancelled_row`, `_overload_observed`, `_overload_skip_row`,
  `_run_adapter`) with no behavior change.
- Tests: determinism at parallelism 1 and 2, error isolation,
  cancellation (pre-start and mid-run), 508 skip, budget exhaustion,
  dispatch interval, consent/passive/unknown-key gates — 15/15 pass.

### P1-3 — Versioned scan profiles — READY FOR REVIEW

- Commit: `75d099e` — `feat(application): add scan profile registry v1 with deterministic plan builder`.
- Files: `src/penx_app/application/scan_profiles.py`,
  `tests/test_scan_profiles.py`.
- Change: built-in profile registry (`passive`, `standard` = preset `a`,
  `web_audit`, `full_assessment`, all v1) plus
  `profile_to_plan` / `build_custom_plan`; deterministic validated
  `ScanPlan` building; preset key sets pinned against
  `resolve_scanner_selection` and the registry.
- Tests: preset equivalence, validation, determinism — 16/16 pass.

### P1-4 — Offline preflight dry-run — READY FOR REVIEW

- Commit: `614d05c` — `feat(application): add offline preflight dry-run with per-scanner availability`.
- Files: `src/penx_app/application/preflight.py`,
  `src/penx_app/bootstrap.py`, `src/penx_app/scanners/tools.py`,
  `src/penx_app/cli/scanner_menu.py`, `tests/test_preflight.py`.
- Change: headless `penx preflight --target ...` starts no adapters;
  reports schedule order, per-scanner availability (bounded,
  failure-tolerant version probes), consent summary; exit codes 0/1/2.
- Tests: zero adapter calls, exit codes, schedule order, consent
  gating, error handling — 49/49 pass.

### P1-5 — Bounded structured runtime diagnostics (metadata v3) — READY FOR REVIEW

- Commit: `2cceca2` — `feat(domain): add bounded structured runtime diagnostics to scanner metadata v3`.
- Files: `src/penx_app/domain/scan_diagnostics.py`,
  `src/penx_app/domain/scan_models.py`,
  `src/penx_app/application/scan_planner.py`,
  `tests/test_runtime_diagnostics.py`.
- Change: `ScannerRunEvent` (`started`/`completed`/`failed`/`skipped`/
  `cancelled`, note ≤ 200 chars, ≤ 8 events per adapter) recorded by the
  scheduled executor; `ScanResult.metadata()` emits version 3 (per-row
  `events` + top-level `plan` block); event-free results stay
  byte-identical v1/v2 (fixture-asserted); `from_metadata` accepts
  versions 1/2/3 with strict v3 validation; size cap unchanged
  (≤ 100 000 bytes).
- Tests: round-trip, byte-identical v1/v2 fixtures, caps, determinism —
  34/34 pass.

### Phase 1 verification

- Date: 2026-10-21, branch `feature/phase1-orchestration`.
- `python offline_tests.py`: `[OK] All 204 PenX offline test suites
  passed.` (198 baseline + 6 new Phase-1 suites; 138 new tests).
- Ruff: clean (`E9,F63,F7,F82` full tree; `F401` over `src/penx_app`).
- mypy: clean over the full `src/penx_app` tree (103 files) with the CI
  flags and the CI Linux platform selection. (On Windows the same
  command reports 15 pre-existing platform-attribute errors in
  `cli_navigation.py`, `process_runner.py`, and `report_batch.py` —
  none of them touched by this branch.)
- Acceptance mapping: every roadmap.md §1.4 item maps to passing tests
  (see `plan.md` §9 and the PR description).
- Open risks: see `plan.md` §10 (sequential path untouched; shared 508
  guard helpers; metadata v3 additive; bounded preflight probes).
- PR: https://github.com/spk-c/PenX/pull/100 (no auto-merge).
- Next step: merge after review; then Phase 2 (evidence traceability and
  trustworthy scan comparison).
