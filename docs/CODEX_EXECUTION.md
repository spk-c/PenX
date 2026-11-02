# PenX — Codex execution playbook

**Roadmap source:** [ROADMAP.md](ROADMAP.md). The repository [AGENTS.md](../AGENTS.md) contains short permanent constraints. This playbook is for **implementing one item at a time**, not for treating all roadmap entries as one unlimited change request.

## Start here: recommended first task

**PX-003 — golden scanner fixture inventory and harness.** This is the most valuable foundation for subsequent scanner/finding/AI improvements. Existing tests and Kali local fixtures already cover much of the ground, so Codex must first report coverage and add **only genuine missing cases**, not duplicate hundreds of tests.

### Copy into Codex

> You are working in https://github.com/spk-c/PenX on the current main branch. Read AGENTS.md, docs/ROADMAP.md and docs/CODEX_EXECUTION.md. Start with roadmap item **PX-003 only**. Inspect every scanner adapter and its parser, existing tests and tests/kali_local_scanner_acceptance.py; make a short coverage map of COMPLETE/PARTIAL/FAILED, timeout, cancellation, corrupted output and missing dependency cases. Identify at least one source-grounded gap with real user impact, add sanitized deterministic offline fixtures and tests, then implement only the minimal code changes needed. Do not scan any external target, enable active probes, run exploitation or change existing consent behavior. Preserve historical schema/API and do not alter releases or tags. Run targeted tests, python offline_tests.py and relevant static checks; if something cannot run, say NOT RUN. Make small meaningful commits, push the feature branch after each completed slice, create a PR referencing PX-003 and record test commands/results and remaining issues. After the PR, stop and report; do not start another roadmap item automatically.

## Workflow Codex must follow

1. **Orientation.** Print branch/HEAD, read roadmap ID, inspect files and tests. Check open issues and PRs, compare current behavior to the roadmap; explicitly identify implemented/partial/missing.
2. **Mini design.** Write a 10–20-line plan in the PR or a short docs/dev note covering constraints, new contracts, migrations, safety and rollback. No unrelated scanner additions.
3. **Acceptance first.** List exact test cases and expected outcomes, including false-positive and scope boundaries. Make a failure reproducible offline before changing a parser or behavior.
4. **Minimal vertical implementation.** Prefer extending existing interfaces. Avoid altering versioned JSON/SARIF without an additive compatibility plan. Keep time/memory/net budgets explicit.
5. **Testing.** Run relevant test modules, full offline suite and distribution validation; add Windows/Linux/Kali/DB checks when pertinent. Separate true executed results from not-run/manual gates. No third-party production scans.
6. **Diff and security review.** Check secrets, path traversal, unbounded reads, shell interpolation, regressions, source provenance, cancellation and authorization. Run git diff --check.
7. **Checkpoint and push.** Commit and push complete, tested slices, update PR summary/test evidence. No force push to main and no blind auto-merge.
8. **Exit.** Provide commit/PR URLs, changed paths, tests (PASS/FAIL/NOT RUN), migration/rollback notes, unresolved items and the next eligible PX ID.

## Hard blockers

Stop and request user authorization for: real external hosts or accounts; active security scans beyond the approved local fixture; CI or package publication; GitHub secrets/tokens; real database migration/restore; enabling scheduled background network tasks; expanding scope to discovered assets; changing release tags or main protection; adding exploit payloads.

Stop implementation and mark BLOCKED (do not fabricate success) if source equivalence cannot be resolved, a schema change would silently break historical data, scope cannot be validated, or required tests are failing.

## Pull request template

**Title:** feat(scope): PX-### — short behavior

**Body:**
- Problem and user-visible outcome
- Current behavior and overlapping features checked
- Design/API and data compatibility (including safe failure handling)
- Consent/target/network/secrets impact
- Changes and deliberately out-of-scope items
- Test evidence: command, platform, status, suite counts where known
- Backward compatibility, migration/rollback
- Remaining manual/field acceptance
- Next recommended PX ID

## Phase order and dependencies

| First | Then | Defer until foundation |
| --- | --- | --- |
| PX-003 (corpus), PX-002 (result taxonomy) | PX-101 (explicit scope manifest), PX-004 (backup/restore) | PX-102 (job queue) |
| PX-101 + PX-102 | PX-104 (workspace), PX-103 (TUI) | PX-105/106 (recurrence/alerts) |
| PX-201 (lifecycle) + PX-203 (evidence) | PX-202, PX-204, PX-205/206 | Optional read-only localhost UI |
| PX-301/302/303 (bounded read-only checks) | PX-304/305, PX-307 | PX-306 (third-party adapter contract) |
| PX-402 + PX-403 (grounding + benchmark) | PX-401/404/405 | Autonomous or cloud-driven assessments (not in this roadmap) |

## Safe scope and example commands

Example **documentation-only** names such as example.test and RFC5737/3849 addresses must never be treated as real authorized targets. Use local loopback fixture servers and synthetic reports.

- python offline_tests.py --list
- python offline_tests.py
- python scripts/validate_distributions.py
- python scripts/refactor_benchmarks.py (if applicable)
- python scripts/validate_field_acceptance.py <sanitized-worksheet> --allow-incomplete (only when a worksheet is provided; does not sign off real-world testing)

For packaging-related work, inspect .github/workflows/ci.yml, linux-packaging.yml, release.yml and tests/test_release_pipeline_contracts.py. Do not tag a release for a documentation/feature PR.

## Prioritization for future Codex turns

Ask Codex to complete one PX item or a scoped subset, not 'implement entire roadmap'. If a phase requires multiple PRs, retain one tracked issue/PR per vertical slice, with dependency links and acceptance evidence. Prefer reproducible improvements in false-positive control, data integrity and usability over adding 20 shallow scanner integrations.
