# PenX Roadmap

Canonical phase plan for the modular security-orchestration program.

- Source brief (full requirements): `roadmap.md` in the repository root (2026-10-21)
- Progress tracker: `docs/ROADMAP_PROGRESS.md`
- Architecture audit and implementation packages: `docs/ARCHITECTURE_PLAN.md`

Status values: `NOT STARTED`, `IN PROGRESS`, `IMPLEMENTED`, `TESTED`, `READY FOR REVIEW`, `COMPLETE`, `BLOCKED`.

| Phase | Scope | Priority | Status (2026-10-21) |
| --- | --- | --- | --- |
| 0 | Repository audit and development baseline | prerequisite | COMPLETE |
| 1 | Scanner orchestration and flexible scan profiles | very high | COMPLETE |
| 2 | Evidence traceability and trustworthy scan comparison | very high | COMPLETE |
| 3 | JSON/SARIF reporting and CI/CD integration | high | COMPLETE |
| 4 | Typed per-scanner configuration | high | NOT STARTED |
| 5 | Guided mode for beginners | medium | NOT STARTED |
| 6 | Extended local AI automation | later | NOT STARTED |

## Phase 0 — Repository audit and development baseline

**Status: COMPLETE (2026-10-21).**

Scope: full architecture audit (`application`, `scanners`, `domain`, `reporting`,
`analysis`, `cli`, `storage`, `tests`, CI workflows), baseline test run, technical
debt inventory, measurable quality goals, and small separable Phase 1 packages.

Acceptance: documented current state, prioritized tasks, successful unchanged
baseline tests. All satisfied — see `docs/ARCHITECTURE_PLAN.md` (audit) and
`docs/ROADMAP_PROGRESS.md` (baseline run records).

## Phase 1 — Scanner orchestration and flexible scan profiles

**Priority: very high. Status: COMPLETE (PR #100 merged).**

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

**Priority: very high. Status: COMPLETE (2026-10-22).**

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

**Priority: high. Status: COMPLETE (2026-10-22).**

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
  coverage; configurable Nuclei-match severity threshold.
- Optional manual-only GitHub Actions workflow with authorization, quoted
  target inputs, SARIF upload and preserved policy exit codes.
- Standalone `penx-assessment-v1` and distinct `penx-scan-v1` JSON schemas.

## Phase 4 — Typed per-scanner configuration

**Priority: high. Status: NOT STARTED.**

Existing: per-scanner timeouts via `PENX_<NAME>_TIMEOUT` env vars
(`scanners/tools.py::_scanner_timeout`, clamped 30–900 s),
`PENX_NUCLEI_TEMPLATE_TIMEOUT`, `PENX_LLM_TIMEOUT`.

Open items (brief §4): strict typed schema with argument allowlists, no shell
interpolation, no automatic scope expansion, no consent bypass; bounded
resource budgets; profile-scoped settings; safe import/export/validation of
custom profiles; secrets never stored in exported profiles.

## Phase 5 — Guided mode for beginners

**Priority: medium. Status: NOT STARTED.**

Current UX is advanced-first (`cli/app.py::_recon_choice_menu`). The guided
mode must add plain-language scanner descriptions, profile recommendations,
scope/consent/risk explanations, pre-scan previews, and confidence/severity/
evidence explanations without restricting the advanced flow (brief §5).

## Phase 6 — Extended local AI automation

**Priority: later (after Phases 1–5 stabilize). Status: NOT STARTED.**

Existing: OpenAI-compatible local endpoint support, AI tool protocol
(`analysis/ai_tool_protocol.py`), schema-validated structured output, bounded
prompts, hallucination corrections (`domain/corrections.py`).

Constraints (brief §6): core orchestration must work fully without AI; no
unattended scope expansion; no AI-driven shell commands; no cloud dependency
for base features.

## Cross-cutting engineering standards

The standards in the brief apply to every phase: no rewrites of working
components; domain logic independent of CLI/database/scanner processes;
backward compatibility for CLI, database, reports, and presets; authorized
scope + consent for every network scan; Windows primary with Linux
preserved; Python 3.10/3.11/3.12 support; bounded large-output processing;
migration-safe persistence; updated documentation; all relevant tests before
every PR; offline fixtures only (no unauthorized live tests).
