# PenX — Codex execution playbook

**Roadmap source:** [ROADMAP.md](ROADMAP.md). The repository [AGENTS.md](../AGENTS.md) contains short permanent constraints. This playbook is for **implementing one item at a time**, not for treating all roadmap entries as one unlimited change request.

## Start here: current main and next verified gap (4 November 2026)

**Merged source is not a released binary or field sign-off.** The published
release remains v0.6.0. The [roadmap tracker #123](https://github.com/spk-c/PenX/issues/123)
and the [updated snapshot](ROADMAP.md) distinguish implementation,
CI evidence, operator acceptance, and release status. Never assume all
36 roadmap items are implemented because a few PRs passed.

**Do not recreate merged starter work.** In addition to earlier PX-002/003
provenance and PX-101 scope slices, main includes [#162](https://github.com/spk-c/PenX/pull/162)
(explicit project asset approval/revocation), [#163](https://github.com/spk-c/PenX/pull/163)
(SQLite WAL-sidecar refusal), [#164](https://github.com/spk-c/PenX/pull/164)
(strict backup manifest), [#165](https://github.com/spk-c/PenX/pull/165)
(offline labelled AI fixture scorer) and [#166](https://github.com/spk-c/PenX/pull/166)
(manual CI/SARIF workflow hardening). No real model, production database
restore or target scan was exercised by those PRs.

**Next P0 design/code slice: PX-004 historical MariaDB dump verification.**
The current checksum pairs protect local file identity, and optional scratch
audits compare *current*, separately observed source/scratch rows. They do
not prove the actual saved SQL's provenance, semantic validity or
historical contents. Implement one small offline, deliberately
fail-closed diagnostic/fixture step that identifies untrusted dump
constructs without claiming a general SQL parser or enabling imports.
Start with real disposable `mariadb-dump` fixtures and negative tests;
reject ambiguous syntax and avoid any live restore. Do not silently loosen
the existing conservative MariaDB gates.

**Parallel operator acceptance remains separate:** PX-001/PX-003 Windows,
Kali/Npcap, real old databases and report review; PX-101 blocked external
adapters need per-adapter scope/rate/redirect audits. PX-102 persistent jobs
cannot auto-resume active work until those grants and PX-004 recovery
guarantees are demonstrated. PX-403's offline benchmark is not an actual
NInfer/Strata accuracy result, and PX-501's workflow is manual only.

### Copy into Codex

> Work in https://github.com/spk-c/PenX. Read AGENTS.md, ROADMAP.md,
> CODEX_EXECUTION.md and open PRs/issues first. Do **one PX-004 P0
> non-executing SQL-dump diagnostic slice** only, against bounded synthetic
> and disposable CI MariaDB dump fixtures. State up front what the
> diagnostic can and cannot prove; no user DB credentials, production
> restore, arbitrary SQL execution, external network scans or release
> publication. Add negative tests for malformed dump statements, hidden
> executable comments, delimiter/charset traps, statement reordering,
> SQL injection payloads and incomplete files. Keep all existing
> `restore_available: false` semantics, preserve old backup manifests,
> and reject ambiguous syntax rather than treating it as verified.
> Run focused and complete offline tests, static checks and relevant
> disposable CI, then submit one reviewable PR referencing #123. Record
> Windows/field tests as NOT RUN unless actually observed, and stop at
> the accepted PR boundary. Never mark PX-004 or the entire roadmap done
> from synthetic CI alone.

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
