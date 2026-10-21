# PenX Phase 1 Implementation Plan — Scanner Orchestration & Scan Profiles

**Status:** Final (Phase 0 complete, PR #98 merged as `bee1ba5`)
**Base:** `main` @ `d03a6b3` — green baseline 7a32d19, 197/197 suites OK, exit 0
**Branch:** `feature/phase1-orchestration` (created from `main`, one conventional commit per package)
**Sources:** `roadmap.md` §Phase 1 & §1.4, `docs/ROADMAP.md`, `docs/ARCHITECTURE_PLAN.md` §7 (packages P1-1…P1-5)

---

## 1. Goals

Deliver the controlled scan-execution foundation the brief demands for Phase 1:

1. A versioned, domain-pure `ScanPlan` contract with profiles, budgets, consent and parallelism as first-class fields.
2. A planner/executor that runs a plan with configurable parallelism, per-scanner timeouts, a global budget, a conservative HTTP 508 guard, cooperative cancellation and deterministic result aggregation — without changing any existing behavior when `max_parallelism == 1`.
3. A profile registry v1 with built-in profiles and a stable profile API, plus a deterministic custom-plan builder.
4. A dry-run / preflight capability that reports scanner availability, versions, missing prerequisites, scope and budget before any adapter starts.
5. Structured, bounded runtime diagnostics inside the persisted scanner metadata (additive, version 3).

## 2. Non-Goals

- No changes to individual scanner adapters (their CLI flags, parsers, output formats).
- No changes to the existing interactive scan flow's user-visible behavior (menus, presets a/n/x, consent prompt).
- No per-scanner request-rate shaping inside adapters (that is Phase 4 per-scanner configuration; Phase 1 limits *dispatch* rate only).
- No new report formats, no DB schema migration, no LLM prompt changes.
- No changes to storage, evidence anchoring semantics, or the passive recon module.

## 3. Ground Rules

- **Backward compatibility:** existing entry points keep their signatures. `run_selected(request, *, menu, emit, cancel_event)` and `run_selected_structured(...)` keep their exact behavior for `max_parallelism == 1` plans. `ScanRequest` is untouched.
- **Domain purity:** `domain/scan_plan.py` may import only stdlib + `penx_app.scanners.registry` (for key/consent validation). It must not import `cli`, `storage`, `reporting`, `requests`, `subprocess`, `sqlite3`, `urllib` (enforced by `tests/test_architecture_boundaries.py`).
- **Offline tests:** every new suite is a `tests/test_*.py` unittest module, auto-discovered by `offline_tests.py`, no network, no real subprocess scanners, no `input()` reads. Mock-adapter pattern as established in `tests/test_typed_scanner_dispatch.py` (`menu={"1": ("Nmap", lambda target: ...)}`), `tests/test_scan_sequence_cancel.py`, `tests/test_scanner_choice_contracts.py`.
- **Verification gates:** `python offline_tests.py` (baseline 197 suites must stay green plus all new suites), `ruff check` per CI config (E9, F63, F7, F82 + F401 on staged/`src/penx_app` full-tree), `mypy` 3.10 per the CI full-tree gate over `src/penx_app`.
- **Python 3.10 syntax only.** Windows-first (process-group teardown semantics from `process_runner` unchanged).
- **One conventional commit per package** on the branch; a single PR per phase with risk notes per `roadmap.md` §Git/PR workflow.
- **Consent/scope safety:** an active consent key is never dispatched without `active_consent == True`; passive-only plans dispatch no active adapter; all of this is validated *before* any adapter call.

---

## 4. Package P1-1 — `ScanPlan` domain type

### 4.1 New file: `src/penx_app/domain/scan_plan.py`

```python
@dataclass(frozen=True)
class ScanPlan:
    profile_id: str              # non-empty, e.g. 'standard'
    profile_version: int         # >= 1
    target: str                  # non-empty; raw (normalization stays in application layer)
    scanner_keys: tuple[str, ...]  # registry keys, e.g. ('1', '3'); empty only if passive_only
    passive_only: bool
    active_consent: bool
    per_scanner_timeouts: dict[str, int]   # registry key -> seconds, each 30..900
    max_parallelism: int         # >= 1, strict int (bool rejected)
    global_budget_seconds: int | None      # None or int >= 30
    dispatch_interval_seconds: float | None # None or finite > 0 (rate-limit hook)
```

### 4.2 Validation — `validate_plan(plan) -> list[str]`

Returns all violations (empty list = valid); also a `PlanValidationError` raised by `assert_valid_plan`. Rules:

| # | Rule |
|---|------|
| R1 | `profile_id` non-empty str; `profile_version` strict int ≥ 1 |
| R2 | `target` non-empty str (whitespace-only rejected) |
| R3 | `scanner_keys` is a tuple of unique registry keys, each present in `SCANNERS` |
| R4 | `passive_only == True` ⇒ `scanner_keys == ()` and `active_consent == False` (passive collection runs on the passive path; the active executor rejects it today with `ValueError('Passive collection cannot dispatch active scanner adapters.')`) |
| R5 | `passive_only == False` ⇒ `scanner_keys != ()` |
| R6 | any key in `CONSENT_KEYS` (`frozenset({'7','9','e','c'})` per `registry.py`) ⇒ `active_consent == True` |
| R7 | `per_scanner_timeouts`: keys ⊆ `scanner_keys`; each value strict int in `30..900` (mirrors `_scanner_timeout` clamp in `scanners/tools.py`) |
| R8 | `max_parallelism`: strict int ≥ 1 |
| R9 | `global_budget_seconds`: `None` or strict int ≥ 30 |
| R10 | `dispatch_interval_seconds`: `None` or finite number > 0, ≤ 60 |

### 4.3 `ScanPlan.to_request() -> ScanRequest`

1:1 mapping to the existing frozen `domain.scan_models.ScanRequest(target, scanner_ids, passive_only, active_consent)`. Budgets/parallelism live only on the plan (the executor consumes the plan, not the request).

### 4.4 Tests — `tests/test_scan_plan.py`

- R1–R10 each: valid case + at least one violating case per rule (e.g. duplicate key, unknown key `'z'`, consent key without consent, timeout 29/901/`True`, parallelism `0`/`True`, budget `29`).
- `to_request()` round-trips all four fields.
- Passive plan: keys `()`, consent `False` → valid; passive with keys → R4 violation.
- Full registry plan: all 13 keys (`'1'..'9'`, `'e'`, `'s'`, `'c'`, `'d'`) requires consent → valid with `active_consent=True`.
- `validate_plan` returns *all* violations at once (multi-error case).

### 4.5 Commit

`feat(domain): add versioned ScanPlan contract with budgets and consent rules`

---

## 5. Package P1-2 — Planner + controlled executor

### 5.1 New file: `src/penx_app/application/scan_planner.py`

```python
def build_schedule(plan: ScanPlan) -> tuple[str, ...]:
    """Dispatch order for a validated plan. Phase 1: registry order filtered by
    plan keys, deduplicated, stable. (Dependency-aware ordering is a later phase;
    the signature stays stable.)"""

@dataclass(frozen=True)
class PlannedNode:
    key: str
    position: int          # index in build_schedule output
    timeout_seconds: int   # resolved per R7/env/default

def resolve_node_timeout(plan: ScanPlan, key: str) -> int:
    """plan.per_scanner_timeouts[key]  >  PENX_<ID_UPPER>_TIMEOUT env  >  built-in default."""

def run_plan(plan: ScanPlan, *, menu: dict, emit=lambda *_: None,
             cancel_event: threading.Event | None = None) -> ScanResult:
    """Execute a validated plan; returns ScanResult with rows in plan order."""
```

### 5.2 Behavior specification

1. **Validation gate:** `run_plan` first asserts the plan via P1-1 rules; any violation raises `PlanValidationError` *before* touching `menu` or calling any adapter.
2. **Passive guard:** `passive_only` plan ⇒ same `ValueError` as today (`'Passive collection cannot dispatch active scanner adapters.'`), raised before any adapter call.
3. **Consent gate:** consent keys without consent ⇒ `PlanValidationError` before any adapter call (today's `run_selected` message is preserved for the `ScanRequest` path; the plan path uses the P1-1 rule text).
4. **`max_parallelism == 1` (default, zero behavior change):** delegate to the existing sequential path — `run_selected`/`run_selected_structured` semantics exactly as in `application/scanner_execution.py` today: per-adapter `try/except` → `FAILED` with 220-char detail; 508 guard regex `(?im)^HTTP\s+508(?:\s|$)` or `'508 resource limit is reached'` scanned over completed `http headers`/`web fingerprint`/`nmap` outputs skips later `resource_sensitive` scanners with `PARTIAL` + diagnostics `'Skipped after HTTP 508 from a previous selected scanner'`; cancel ⇒ pending nodes `PARTIAL` `'Not started: caller cancelled scan sequence'`; legacy non-`ScannerOutput` returns wrapped with the existing heuristic.
5. **`max_parallelism > 1` (new):** a scheduler dispatches nodes in plan order onto `concurrent.futures.ThreadPoolExecutor(max_workers=plan.max_parallelism)`:
   - Same per-node adapter contract (`_call_adapter` inspection of the `cancel_event` parameter), same per-adapter `try/except` isolation, same `ScannerOutput` normalization.
   - **508 guard at dispatch time:** before starting a node, the scheduler checks completed results so far with the *same* 508 detection; a `resource_sensitive` node dispatched into overload gets the same skip `ScannerOutput` (PARTIAL, no execution). Nodes already in flight are allowed to finish (documented).
   - **Cancellation:** `cancel_event` set ⇒ scheduler stops dispatching; pending nodes receive the same `PARTIAL` not-started records; in-flight nodes get the event through the existing cooperative port. Process-group teardown per `process_runner` unchanged.
   - **Global budget:** deadline = start + `global_budget_seconds`. Pending nodes past the deadline get `PARTIAL` with diagnostics `'Not started: global budget exhausted'`; the scheduler then sets the cancel path for in-flight nodes (cooperative, no hard kill).
   - **Dispatch rate limit:** if `dispatch_interval_seconds` is set, the scheduler enforces a minimum interval between adapter *starts* (start-rate limit; deterministic, testable).
   - **Deterministic aggregation:** the returned `ScanResult` always lists rows in plan order (registry order), independent of completion order. Durations are measured per node as today.
6. **Evidence anchoring:** structured output wraps rows exactly as `run_selected_structured` does today (`capture_evidence(row, 0, min(2000, len), kind='adapter_output', parser_version=1)` for evidence rows).

### 5.3 Changes to `src/penx_app/application/scanner_execution.py`

Additive only: expose the 508 detection and the not-started/skip `ScannerOutput` builders as private helpers reused by `scan_planner` (no change to existing function signatures or behavior).

### 5.4 Tests

`tests/test_scan_planner.py`:
- `build_schedule`: registry order, dedup, passive ⇒ `()`, invalid plan raises before scheduling.
- `resolve_node_timeout`: plan override beats env beats default (env via `mock.patch.dict(os.environ, ...)`), clamp bounds honored.

`tests/test_plan_executor.py` (mock adapters throughout; pattern from `test_typed_scanner_dispatch.py` / `test_scan_sequence_cancel.py`):
- **Determinism @ parallelism 1:** two runs, same plan/menu ⇒ identical `ScanResult` (statuses, texts, order; durations excluded from equality).
- **Determinism @ parallelism 2:** 4 independent mock adapters ⇒ same row order as plan order across repeated runs.
- **Concurrency:** two sleep-backed mock adapters with parallelism 2 complete in overlapping time (total wall time < sum of individual sleeps).
- **Error isolation:** one adapter raises `RuntimeError` ⇒ its row `FAILED` with truncated detail, others `COMPLETE`.
- **Cancellation before start:** pre-set `cancel_event` ⇒ all rows `PARTIAL` not-started, zero adapter calls (call counter).
- **Cancellation mid-run:** slow first adapter, fast cancel ⇒ pending rows `PARTIAL`, in-flight row finishes or marks per contract.
- **508 guard (parallel):** first adapter emits `HTTP 508 ...` ⇒ later resource-sensitive row skipped with the exact diagnostics string; non-sensitive row still runs.
- **Budget:** two 2 s adapters, budget 3 s with parallelism 1 ⇒ second node `PARTIAL` budget-exhausted.
- **Rate limit:** 3 nodes, `dispatch_interval_seconds=0.5` ⇒ start timestamps respect the interval (mock clock / short sleeps).
- **Consent/passive gates:** no `menu` call happens on rejected plans (counter stays 0).

Existing suites must stay green unchanged: `test_scan_sequence_cancel.py`, `test_typed_scanner_dispatch.py`, `test_scanner_choice_contracts.py`, `test_adapter_provenance.py`, `test_endpoint_inventory_mapping.py`.

### 5.5 Commit

`feat(application): add plan-based scan planner and bounded parallel executor`

---

## 6. Package P1-3 — Profile registry v1 + deterministic plan builder

### 6.1 New file: `src/penx_app/application/scan_profiles.py`

```python
@dataclass(frozen=True)
class Profile:
    id: str
    version: int
    description: str
    scanner_keys: tuple[str, ...]
    passive_only: bool
    default_timeouts: dict[str, int]      # registry key -> seconds (30..900)
    max_parallelism: int
    global_budget_seconds: int | None

def profile_to_plan(profile: Profile, target: str, *, active_consent: bool,
                   per_scanner_timeouts: dict[str, int] | None = None,
                   max_parallelism: int | None = None,
                   global_budget_seconds: int | None = None,
                   dispatch_interval_seconds: float | None = None) -> ScanPlan:
    """Build a ScanPlan; caller-supplied overrides beat profile defaults;
    consent keys still require active_consent (plan validation R6 applies)."""

BUILTIN_PROFILES: dict[str, Profile]  # see 6.2

def list_profiles() -> tuple[Profile, ...]     # stable order, for CLI/reporting
def get_profile(profile_id: str) -> Profile     # KeyError -> unknown profile
```

### 6.2 Built-in profiles (v1)

| id | keys | passive_only | notes |
|----|------|--------------|-------|
| `passive` | `()` | `True` | Matches preset `'0'` / `PASSIVE_ONLY`; no active adapter |
| `standard` | `('1','2','3','4','5')` | `False` | **Exactly** today's preset `a` key set |
| `web_audit` | `('3','4','6','7','8','d')` | `False` | Controlled web/TLS: WhatWeb, HTTP headers, Nikto, Nuclei, httpx, TLS; consent required (`'7'`) |
| `full_assessment` | all 13 registry keys `('1','2','3','4','5','6','7','8','9','e','s','c','d')` | `False` | Full scan incl. endpoint mapping; consent required |
| `custom` | *(not a builtin entry; built via `build_custom_plan` below)* | — | Explicit user selection |

```python
def build_custom_plan(target: str, keys: tuple[str, ...], *, active_consent: bool,
                      **overrides) -> ScanPlan   # profile_id='custom', version=1
```

### 6.3 Tests — `tests/test_scan_profiles.py`

- **Preset compatibility (critical):** `BUILTIN_PROFILES['standard'].scanner_keys == tuple(resolve_scanner_selection('a', menu_keys))` for the full registry menu; `web_audit` keys ⊆ registry, all consent keys present; `full_assessment` keys == `tuple(SCANNERS)` (13 keys).
- Every profile validates via P1-1 (`validate_plan(profile_to_plan(...))` empty).
- `profile_to_plan` override precedence: caller timeout beats profile default; caller parallelism beats profile.
- `web_audit` without `active_consent` ⇒ R6 violation (no plan created).
- `passive` profile plan: `scanner_keys == ()`, `passive_only True`, consent `False`.
- `list_profiles` order stable; `get_profile('nope')` raises; unknown/typo profile ids give a clear error in `build_custom_plan`-free API.
- Menu presets `a`/`n`/`x` and `'0'` remain untouched (covered by existing `test_scanner_choice_contracts.py` staying green).

### 6.4 Commit

`feat(application): add scan profile registry v1 with deterministic plan builder`

---

## 7. Package P1-4 — Preflight / dry run

### 7.1 New file: `src/penx_app/application/preflight.py`

```python
@dataclass(frozen=True)
class ScannerAvailability:
    key: str
    scanner_id: str
    display_name: str
    available: bool
    version: str | None          # best effort, local binary version
    missing: tuple[str, ...]     # e.g. ('nmap',) or ('ruby', 'vendor/whatweb/whatweb')
    note: str                    # <= 200 chars

@dataclass(frozen=True)
class PreflightReport:
    plan: ScanPlan
    schedule: tuple[str, ...]
    availability: tuple[ScannerAvailability, ...]   # one per scheduled key, plan order
    available: bool              # True iff all scheduled scanners available

def scanner_availability(key: str) -> ScannerAvailability: ...
def build_preflight(plan: ScanPlan) -> PreflightReport: ...
def main(argv: list[str]) -> int: ...   # for `penx preflight ...`
```

### 7.2 Availability matrix (offline; reuses existing resolvers, no network, no adapters)

| key | scanner | check (all existing code) |
|-----|---------|---------------------------|
| `'1'` | nmap | `scanner_runtime.find_nmap()` + `npcap_present()` (note if missing) |
| `'2'` | whois | `importlib.util.find_spec('whois')` (library present) |
| `'3'` | whatweb | `find_runtime('ruby')` and `WHATWEB_SCRIPT.is_file()` |
| `'4'` | http_headers | always available (stdlib) |
| `'5'` | dns | `importlib.util.find_spec('dns')` (dnspython) |
| `'6'` | nikto | `find_runtime('perl')` and `NIKTO_SCRIPT.is_file()` |
| `'7'` | nuclei | binary resolvable via the adapter's lookup path |
| `'8'` | httpx | binary resolvable |
| `'9'` | ffuf | binary resolvable |
| `'e'` | endpoint_mapping | Python-only deps resolvable (no external binary) |
| `'s'` | subfinder | binary resolvable |
| `'c'` | katana | binary resolvable |
| `'d'` | tls | always available (stdlib ssl) |

Binary resolvable: a **new public** `scanners.tools.tool_path(tool) -> str | None` wrapper that delegates to the existing private `_executable(tool, '')` (env override `PENX_<TOOL>_PATH` then `shutil.which`), so preflight and adapters share one resolution path. (One-line addition, no rewrite.)

### 7.3 Version detection (best effort, local only)

- Bounded local probe via `scanners/process_runner.run_tool` with `timeout=10`, first non-empty line of stdout as version, `version=None` on any failure. Flags: nmap `--version`, ruby `--version`, perl `--version`, Go tools `-version` where supported (per-tool table in the module), builtins report `'python-3.x (builtin)'`.
- Probes are optional and failure-tolerant: an unavailable version never changes `available`.
- Runtime *banner* versions stay in `intelligence/finding_trace.py` (post-scan); preflight reports *binary* versions. Documented as the two halves of the gap-5 unified view.

### 7.4 Dry-run contract

`build_preflight` never dispatches an adapter and never opens a network connection. The report contains: target, scope note (host as given; no normalization side effects), profile id/version, plan summary (consent, passive, max_parallelism, global budget, dispatch interval), per-scanner availability/version/missing, the planned execution order (`build_schedule`), and a consent reminder when the plan carries consent keys.

### 7.5 CLI integration

- **Headless:** `penx preflight --target <host> [--profile <id>] [--scanners <comma-keys>] [--consent]`
  - New dispatch block in `bootstrap.py` **before** the interactive fallback, same lazy-import style as `--export-session`:
    `if command == 'preflight': from penx_app.application.preflight import main; return main(args[1:])`
  - Exit codes: `0` = plan valid and all scheduled scanners available (or passive profile); `1` = plan/config error or a scheduled scanner missing; `2` = usage error.
- **Interactive:** `cli/app.py::_execute_scan` shows the preflight summary via the existing `emit` channel when a plan-based scan starts (informational; does not block unless the user opts into strict preflight via the existing progress output).
- `USAGE` string in `bootstrap.py` extended with `| preflight`.

### 7.6 Tests — `tests/test_preflight.py`

- One case per registry key with mocked resolvers (`mock.patch` on `shutil.which`, `find_nmap`, `find_runtime`, `npcap_present`, `importlib.util.find_spec`) asserting the exact `missing` tuple and `available` flag (13 cases).
- Version probe: mocked `process_runner.run_tool` returning synthetic `--version` output ⇒ first-line parse; failing probe ⇒ `version=None`, `available` unchanged.
- **No adapters / no network:** `build_preflight` with a spy `menu` dict proves zero adapter calls; assert no `requests`/`socket` usage paths are triggered (mock-based).
- `main([...])` exit codes: usage error `2`, missing scanner `1`, all available `0`.
- Report ordering: `availability` follows `build_schedule` order.
- Determinism: same mocked environment ⇒ identical report (dataclass equality).

### 7.7 Commit

`feat(application): add offline preflight and dry-run report`

---

## 8. Package P1-5 — Structured runtime diagnostics (metadata version 3)

### 8.1 New file: `src/penx_app/domain/scan_diagnostics.py`

```python
@dataclass(frozen=True)
class ScannerRunEvent:
    scanner_id: str
    event: str                  # 'started' | 'completed' | 'failed' | 'skipped' | 'cancelled'
    duration_seconds: float | None
    exit_code: int | None
    note: str                   # <= 200 chars
```

### 8.2 Behavior

- The executor (P1-2 path) records one event per lifecycle transition per node (bounded: ≤ 8 events per adapter, ≤ 100 adapters — same caps as today's metadata).
- `ScanResult.metadata()` emits **version 3** when events are present; otherwise it keeps emitting version 1/2 exactly as today (byte-identical for event-free results). Version 3 adds, per adapter row, `events: [{...}]` and a top-level `plan` summary block (`profile_id`, `profile_version`, `max_parallelism`, `global_budget_seconds`).
- `ScanResult.from_metadata` accepts versions `1`, `2`, and `3`; v1/v2 parsing is unchanged; v3 events are validated (known event names, bounded note length, finite durations, strict int exit codes) and attached to `ScannerResult.diagnostics`-adjacent structured data without altering `status`/`evidence` semantics.
- Human-facing `emit` output stays as today (no console format change).
- Size cap unchanged: encoded metadata ≤ 100 000 bytes, else `ValueError` as today.

### 8.3 Tests — `tests/test_runtime_diagnostics.py`

- Round-trip: build `ScanResult` with events ⇒ `metadata()` ⇒ `from_metadata` preserves events, statuses, evidence.
- **Backward compatibility:** event-free results produce byte-identical v1/v2 JSON to today's `metadata()` (assert exact string against a fixture); `from_metadata` on stored v1/v2 fixtures unchanged.
- Caps: 9th event per adapter and 101st adapter rejected; note > 200 chars rejected; unknown event name rejected on parse.
- Determinism: same execution transcript ⇒ identical v3 JSON.
- Existing provenance suites stay green: `test_adapter_provenance.py`, `test_evidence_boundaries_audit.py`, `test_evaluation_package_boundaries.py`.

### 8.4 Commit

`feat(domain): add bounded structured runtime diagnostics to scanner metadata v3`

---

## 9. Acceptance mapping (brief §1.4 → this plan)

| Acceptance criterion (roadmap.md §1.4) | Package | Test evidence |
|---|---|---|
| Bestehende Scan-Presets funktionieren weiterhin | P1-3 | `test_scan_profiles.py` (preset `a`/`'0'` equality) + existing `test_scanner_choice_contracts.py` green |
| Fehler eines Scanners stoppen unabhängige Scanner nicht unnötig | P1-2 | `test_plan_executor.py` error-isolation cases (sequential + parallel) |
| Cancellation hinterlässt keine verwaisten Prozesse | P1-2 | `test_plan_executor.py` cancellation cases + existing `test_scan_sequence_cancel.py`, `test_windows_scanner_integration.py` green |
| Passive-Only bleibt tatsächlich passiv | P1-1, P1-2 | `test_scan_plan.py` R4, `test_plan_executor.py` passive gate (zero adapter calls) |
| Aktive Scanner starten niemals ohne erforderliche Zustimmung | P1-1, P1-2 | `test_scan_plan.py` R6, `test_plan_executor.py` consent gate (zero adapter calls) |
| Gleicher Plan + gleiche Test-Eingaben ⇒ reproduzierbare strukturierte Ergebnisse | P1-2 | `test_plan_executor.py` determinism cases (parallelism 1 and 2) |
| Orchestrierung ist offline mit Mock-Adaptern testbar | P1-2, P1-5 | all new suites run offline with mock adapters (pattern from `test_typed_scanner_dispatch.py`) |
| Scan-Profile mit Versionierung und deterministischem Plan | P1-1, P1-3 | `test_scan_plan.py`, `test_scan_profiles.py` |
| Dry Run / Preflight ohne Adapter-Start | P1-4 | `test_preflight.py` (zero adapter calls, exit codes) |

## 10. Risks & mitigations

| Risk | Mitigation |
|------|-----------|
| Parallel executor subtly changes sequential behavior | `max_parallelism == 1` delegates to the *existing* code path untouched; determinism tests pin equality at both parallelism levels |
| 508 guard semantics drift in parallel mode | Same detection regex and same skip `ScannerOutput` extracted into shared helpers; dedicated parallel 508 test |
| Metadata v3 breaks stored-report readers | Additive only; v1/v2 byte-identical for event-free results; round-trip + fixture tests |
| Preflight probes slow on locked-down machines | All probes bounded (10 s), failure-tolerant, and behind a single headless entry point |
| Profile key sets drift from menu presets | Profile tests assert equality against `resolve_scanner_selection` output and the registry |
| Scope creep into adapters | Adapters untouched except the one-line `tool_path` wrapper (P1-4) |

## 11. Definition of Done (phase)

1. All five packages committed on `feature/phase1-orchestration` (one conventional commit each, §4.5/§5.5/§6.4/§7.7/§8.4).
2. `python offline_tests.py` green: baseline 197 suites **plus** `test_scan_plan`, `test_scan_planner`, `test_plan_executor`, `test_scan_profiles`, `test_preflight`, `test_runtime_diagnostics`.
3. `ruff` + `mypy` (3.10, full-tree over `src/penx_app`) clean.
4. Every §1.4 acceptance item from `roadmap.md` maps to passing tests (§9 table fully green).
5. `docs/ROADMAP_PROGRESS.md` updated with phase status; PR opened with risk notes, no auto-merge.
