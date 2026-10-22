# PenX Roadmap

Canonical phase plan for the modular security-orchestration program.

- Maintained requirements: this document; acceptance evidence: `ROADMAP_ACCEPTANCE.md`.
- The original external brief (2026-10-21), previously referenced as root
  `roadmap.md`, is absent here and excluded by `.gitignore`. It is not present
  in available Git history. This public document does not reconstruct it.
- Progress tracker: `docs/ROADMAP_PROGRESS.md`
- Architecture audit and implementation packages: `docs/ARCHITECTURE_PLAN.md`

Status values: `NOT STARTED`, `IN PROGRESS`, `IMPLEMENTED`, `TESTED`, `READY FOR REVIEW`, `COMPLETE`, `BLOCKED`.

| Phase | Scope | Priority | Status (2026-10-22) |
| --- | --- | --- | --- |
| 0 | Repository audit and development baseline | prerequisite | COMPLETE |
| 1 | Scanner orchestration and flexible scan profiles | very high | TESTED |
| 2 | Evidence traceability and trustworthy scan comparison | very high | TESTED |
| 3 | JSON/SARIF reporting and CI/CD integration | high | TESTED |
| 4 | Typed per-scanner configuration | high | TESTED |
| 5 | Guided mode for beginners | medium | TESTED |
| 6 | Bounded local AI draft/batch review | later | TESTED |

TESTED denotes automated offline verification, not final field/release acceptance.
The previous blanket COMPLETE labels are superseded by `ROADMAP_ACCEPTANCE.md`.

## Phase 0 — Repository audit and development baseline

**Status: COMPLETE (2026-10-21).**

Scope: full architecture audit (`application`, `scanners`, `domain`, `reporting`,
`analysis`, `cli`, `storage`, `tests`, CI workflows), baseline test run, technical
debt inventory, measurable quality goals, and small separable Phase 1 packages.

Acceptance: documented current state, prioritized tasks, successful unchanged
baseline tests. All satisfied — see `docs/ARCHITECTURE_PLAN.md` (audit) and
`docs/ROADMAP_PROGRESS.md` (baseline run records).

## Phase 1 — Scanner orchestration and flexible scan profiles

**Priority: very high. Status: TESTED (base PR #100 plus dependency-DAG follow-up).**

Scope (brief §1):

- Extend the existing scanner execution; no second parallel engine.
- Validated scan plans before execution.
- Small dependency DAG between scanners.
- Sequential and controlled parallel execution of independent scanners.
- Configurable global and per-scanner timeouts.
- Parallelism and request-rate limits.
- Clean cancellation and process-tree teardown.
- Per-scanner error isolation.
- Deterministic result aggregation.
- Structured runtime diagnostics.
- Scanner availability and version detection.
- Safe handling of missing scanners.
- Traceable progress information.
- Versioned, validated scan profiles: Passive Recon, Standard, Web Audit,
  Full Assessment, Custom.
- Presets `a`, `n`, `x` and the exclusive passive-only mode stay
  backward compatible.
- Preflight and dry-run that run without any network scan.

Existing foundation (no rewrite needed): `scanners/registry.py` (stable IDs,
consent), `application/scanner_selection.py` (pure choice policy),
`application/scanner_execution.py` (sequential run, consent, error isolation,
cancellation), `scanners/process_runner.py` (process-tree teardown, bounded
capture), `domain/scan_models.py` (validated contracts).

Acceptance (brief §1.4): existing presets still work; a scanner failure does not
stop independent scanners; cancellation leaves no orphaned processes;
passive-only stays passive; active scanners never start without required
consent; same plan + same inputs produce reproducible structured results;
orchestration is testable offline with mock adapters.

Implementation packages P1-1 … P1-5: `docs/ARCHITECTURE_PLAN.md` §7.

## Phase 2 — Evidence traceability and trustworthy scan comparison

**Priority: very high. Status: TESTED (2026-10-22; field acceptance open).**

Implemented (PR #94 and follow-ups, base `ad21266`):

- Bounded exact raw evidence slices per finding (≤ 2000 bytes) with quote
  validation, in-memory checksum, and evidence status
  (`domain/evidence.py`, `reporting/finding_trace.py`).
- Persisted scanner metadata v2 with evidence records
  (`domain/scan_models.py`).
- Conservative follow-up states `new` / `still_present` / `severity_changed` /
  `not_observed` / `not_checked` / `scan_failed`; `resolved` only via explicit
  independent verification (`application/scan_trends.py`,
  `reporting/finding_trace.py`).
- Machine reports with scanner provenance, exact raw excerpts, redaction, and
  atomic publication (`reporting/machine_reports.py`).

Phase 2 additions (2026-10-22; see `EVIDENCE_TRACEABILITY.md`):

- Versioned SHA-256 finding identities across sessions, independent of row IDs
  and severity, used for exact comparison matching and JSON/SARIF exports.
- Optional bounded raw captures with full SHA-256 hashes and explicit validator
  references in additive metadata v3; integrity and quote-anchor revalidation.
- Explicit differing-profile/selection warnings and unknown historical context.
- Both sessions' scanner coverage and recorded plan/configuration metadata in
  diff JSON, text, HTML and PDF reports.

## Phase 3 — JSON/SARIF reporting and CI/CD integration

**Priority: high. Status: TESTED (2026-10-22; CI/field acceptance open).**

Implemented:

- `penx --export-session <ID> --format json|sarif [--redact]`
  (`bootstrap.py`, `reporting/machine_reports.py`).
- SARIF 2.1.0 output and JSON schema id `penx-assessment-v1`.
- Redaction (IPv4/IPv6/target masking) and atomic report publication
  (`publish_unique`).

Phase 3 additions (2026-10-22; see `HEADLESS_SCANS.md`):

- Authorized headless `penx scan` using Phase 1 profiles/planner, bounded
  JSON/SARIF output, dry-run and optional raw artifacts, without AI or a DB.
- Explicit exit codes distinguish usage, policy, scanner failure and partial
  coverage; configurable deterministic-finding severity threshold. Nuclei,
  selected HTTP/TLS checks and informational Nmap/Nikto observations are covered.
- Optional manual-only GitHub Actions workflow with authorization, quoted
  target inputs, SARIF upload and preserved policy exit codes.
- Standalone `penx-assessment-v1` and distinct `penx-scan-v1` JSON schemas.

## Phase 4 — Typed per-scanner configuration

**Priority: high. Status: TESTED (2026-10-22; field acceptance open).**

Existing: per-scanner timeouts via `PENX_<NAME>_TIMEOUT` env vars
(`scanners/tools.py::_scanner_timeout`, clamped 30–900 s),
`PENX_NUCLEI_TEMPLATE_TIMEOUT`, `PENX_LLM_TIMEOUT`.

Implemented: strict typed scanner options, fixed argument allowlists, no shell
interpolation, no automatic scope expansion or consent bypass; bounded
profile/headless budgets; context-local profile settings; bounded custom profile
import/export/validation with secret/target/consent fields rejected. Configuration
snapshots are persisted and compared. Node deadlines now signal running adapters
without freeing occupied slots early. See `SCANNER_CONFIGURATION.md`.

## Phase 5 — Guided mode for beginners

**Priority: medium. Status: TESTED (2026-10-22; human usability acceptance open).**

Implemented: separate `penx guided` and main-menu [g] entry with plain-language
scanner descriptions, goal-based profile recommendations, scope/consent/risk
explanations, local preflight, explicit partial-coverage and final-start choices,
and confidence/severity/evidence explanations. Existing advanced flows remain
available. See `GUIDED_MODE.md`.

## Phase 6 — Extended local AI automation

**Priority: later (after Phases 1–5 stabilize). Status: TESTED for bounded draft/batch review; broader original scope unverified.**

Existing: OpenAI-compatible local endpoint support, AI tool protocol
(`analysis/ai_tool_protocol.py`), schema-validated structured output, bounded
prompts, hallucination corrections (`domain/corrections.py`).

Constraints (brief §6): core orchestration must work fully without AI; no
unattended scope expansion; no AI-driven shell commands; no cloud dependency
for base features.

Implemented after green Phase 1–5 regression gates: explicit `penx review-scan`
performs bounded local-only single/batch draft triage of existing headless reports. Exact
citations and source fingerprints are checked; suggested scanners stay within
recorded selection. Drafts never modify findings/policy or dispatch actions.
Loopback-only transport disables redirects, environment proxies, discovery and
retries. See `LOCAL_REVIEW.md` for bounds and human-review limitations.

## Cross-cutting engineering standards

The standards in the brief apply to every phase: no rewrites of working
components; domain logic independent of CLI/database/scanner processes;
backward compatibility for CLI, database, reports, and presets; authorized
scope + consent for every network scan; Windows primary with Linux
preserved; Python 3.10/3.11/3.12 support; bounded large-output processing;
migration-safe persistence; updated documentation; all relevant tests before
every PR; offline fixtures only (no unauthorized live tests).
