# PenX — Codex execution playbook

**Roadmap source:** [ROADMAP.md](ROADMAP.md). The repository [AGENTS.md](../AGENTS.md) contains short permanent constraints. This playbook is for **implementing one item at a time**, not for treating all roadmap entries as one unlimited change request.

## Start here: current main and next verified gap (3 November 2026)

**Do not repeat the old PX-003/PX-002 starter PRs.** Main includes the merged PX-003 corpus slices [#124–#131](https://github.com/spk-c/PenX/pulls?q=is%3Apr+PX-003), PX-002 taxonomy [#132](https://github.com/spk-c/PenX/pull/132), PX-001 Kali worksheets [#133](https://github.com/spk-c/PenX/pull/133), PX-101 asset registry [#134](https://github.com/spk-c/PenX/pull/134), PX-004 SQLite backup [#135](https://github.com/spk-c/PenX/pull/135), PX-005 release provenance [#136](https://github.com/spk-c/PenX/pull/136) and the PX-103 plain-mode foundation [#137](https://github.com/spk-c/PenX/pull/137). This is source progress, **not full feature acceptance**. The latest published binaries are still v0.6.0.

**First recommended implementation slice: PX-101 runtime authorization enforcement.** The project CLI stores/verifies approved assets, but the project registry does **not** yet protect scanner dispatch. Add explicit project-bound authorization without weakening the existing independent explicit-consent CLI path. Before a runnable job queue (PX-102), enforce approved exact target, expiry, scope/rate/budget and fail-closed behavior at the scan dispatch boundary. Keep discovered assets as candidates; no silent authorization, no new live targets, no batch scans in this slice. P0 evidence/field gaps PX-001/PX-003/PX-004 remain open and may block implementation/release.

### Copy into Codex

> You are working in https://github.com/spk-c/PenX. Read AGENTS.md, docs/ROADMAP.md, docs/CODEX_EXECUTION.md and the latest merged code on main; check open PRs/issues and avoid duplicate implementations. Work on **one PX-101 follow-up slice only**: ensure an explicitly selected project and its approved asset policy are validated at the *actual scanner dispatch boundary*, including expiry and configured rate/budget limits. Keep standalone scans and existing explicit user consent backward compatible. Do not enable batch scanning, auto-approve discovered targets, contact unrelated external systems, publish releases or rewrite history. First document a threat model and an offline failing test matrix for unauthorized/expired/candidate/ambiguous targets, redirects, concurrent revocation and cancellation. Use owned loopback fixtures; no live third-party scans. Make the smallest typed/migration-safe changes needed, run targeted tests, python offline_tests.py, static checks and relevant CI, push a focused branch and open a PR linking Issue #123. State clearly what remains NOT RUN and stop after the PR. Do **not** start PX-102 until the dispatch-authorization acceptance is proven.

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

## Phase order and dependencies (current)

| First (remaining acceptance) | Then | Still blocked |
| --- | --- | --- |
| PX-001/PX-003/PX-004 P0 field/evidence/recovery gaps; PX-101 explicit dispatch authorization | PX-102 persisted and resumable jobs after signed-off project gate | Project batch/scheduled scans and other unattended activity |
| PX-103 live progress / keyboard field checks and PX-104 filtered history | PX-201 review lifecycle and PX-203 evidence quality | PX-105/106 scheduling/alerts without approved jobs and scopes |
| PX-301/302/303 read-only fixture analysis, PX-402/403 model grounding + benchmark | PX-304–307 and PX-401/404/405 after review | No cloud-driven or unauthorized assessment automation |

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
