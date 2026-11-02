# PenX coding-agent guidance

PenX is a Windows/Kali/Linux terminal security-reconnaissance application for **explicitly authorized defensive assessments**. Preserve its evidence and scope boundaries.

## Read before working
- [Technical roadmap](docs/ROADMAP.md) — prioritized features and acceptance criteria.
- [Codex execution protocol](docs/CODEX_EXECUTION.md) — one-PR-at-a-time workflow.
- [Architecture](docs/DEVELOPMENT.md), [scanner behavior](docs/SCANNING_AND_REPORTS.md), [field acceptance](docs/FIELD_ACCEPTANCE.md), [Linux acceptance](docs/LINUX_ACCEPTANCE_2026-11-02.md).
- Confirm the current branch, latest release, existing implementation and overlapping PRs; roadmap descriptions may become stale.

## Invariants
- No scanning outside explicit scope or without required consent; no implicit discovered-asset expansion. Passive-only cannot launch active adapters.
- No exploit execution, stealth, credential attacks or auto-remediation. Do not invent vulnerability verification from model text, versions or missing scanners.
- Preserve scanner COMPLETE/PARTIAL/FAILED and evidence provenance, cancellation, bounded network/subprocess execution and stable CLI/schema compatibility.
- Default local/offline and secret-safe. Never commit tokens, real target details, user databases or unredacted scan records.
- Prefer domain/application/scanner/storage/reporting boundaries already in src/penx_app/. Avoid new parallel frameworks and giant refactors.
- Keep docs, CLI help, fixtures, regression tests, release asset instructions and exact error semantics in sync. Human field sign-off is not replaceable with synthetic CI.

## Implementation and tests
- Work on a focused feature branch. Keep PRs independently reviewable; push completed slices and document commands/results.
- Start with a failing deterministic regression or corpus fixture. Test negative paths: malformed data, duplicate records, timeouts, permission denial, partial scan, cancellation and privacy.
- Baseline checks: python offline_tests.py, python scripts/validate_distributions.py; additionally run targeted tests and relevant package/CI smoke tests. If local platform cannot run a check, state NOT RUN, never PASS.
- Never rewrite an immutable release tag or publish releases/packages without a separate explicit request. Do not bypass protected main or turn on CI network scans.
- For high-risk interface or persistence changes, create a short design note and migration/rollback plan before coding.

## Delivery
Link the roadmap item ID (PX-###), describe implemented vs deferred scope, tests and evidence, and remaining limits. Open/update a PR instead of claiming all roadmap phases are finished.
