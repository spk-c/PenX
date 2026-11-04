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
(manual CI/SARIF workflow hardening). Follow-up source includes
[#168](https://github.com/spk-c/PenX/pull/168) and
[#169](https://github.com/spk-c/PenX/pull/169) (offline lexical SQL-dump diagnostics),
[#170](https://github.com/spk-c/PenX/pull/170) (redacted read-only SQLite
history pagination), and [#171](https://github.com/spk-c/PenX/pull/171)
(local CycloneDX/SPDX inventory parsing), plus
[#173](https://github.com/spk-c/PenX/pull/173) (two operator-held MariaDB
SQL/manifest SHA-256 pins, file identity only),
[#174](https://github.com/spk-c/PenX/pull/174) (local exact OSV version
candidate comparisons), and [#175](https://github.com/spk-c/PenX/pull/175)
(saved-report evidence traceability 0–2 with JSON/SARIF/HTML/PDF parity).
These are **partial** roadmap slices; no real model, production database restore or external target scan
was exercised. The [36-item acceptance matrix](ROADMAP.md#acceptance-matrix--all-36-roadmap-ids-4-november-2026)
is the source of tracked remaining gates.

**Next P0 design/code slice: PX-004 historical dump provenance and safe
recovery gates, NOT another lexical inspector.** [#168](https://github.com/spk-c/PenX/pull/168)
and [#169](https://github.com/spk-c/PenX/pull/169) already identify
suspicious SQL text and unclosed lexical tails, including actual disposable
native MariaDB dump integration. [#173](https://github.com/spk-c/PenX/pull/173)
adds two out-of-band hash pins, so do **not** repeat an external file-identity
check as if it proved signed origin or historical row integrity. **Neither proves that the saved SQL matches
the source snapshot**, can be executed safely, or is complete. Design a
reviewable, *non-mutating* historical dump-vs-scratch validation contract
with trusted source evidence and a bounded fixture corpus. Distinguish
original source, saved bytes, scratch imported rows and dates/times; do not
equate separate present-day snapshots to historical parity. Preserve all
`restore_available:false` contracts. No live/in-place MariaDB restore,
operator data access or new automatic jobs without separately approved
recovery and scope sign-off.

**Parallel operator acceptance remains separate:** PX-001/PX-003 Windows,
Kali/Npcap, real old databases and report review; PX-101 blocked external
adapters need per-adapter scope/rate/redirect audits. PX-102 persistent jobs
cannot auto-resume active work until those grants and PX-004 recovery
guarantees are demonstrated. PX-403's offline benchmark is not an actual
NInfer/Strata accuracy result, and PX-501's workflow is manual only.

### Copy into Codex

> Work in https://github.com/spk-c/PenX. Read AGENTS.md,
> docs/ROADMAP.md (the 36-ID acceptance matrix), docs/CODEX_EXECUTION.md
> and all open PRs/issues first. Do **one new PX-004 non-mutating
> historical dump-content/source provenance safety slice** after merged
> PRs #168/#169 and dual external hash pins #173, rather than
> recreating lexical dump checks or file-identity-only validation.
> Use bounded disposable synthetic/CI MariaDB fixtures; no real database
> credentials, no production restore/import, no external network scans,
> no public release or unauthorized automated jobs. Document exactly
> what a scratch comparison can/cannot prove and never mark historical
> parity from a separate current-source snapshot. Keep
> `restore_available:false`; preserve old manifests and CLI contracts.
> Run focused and full offline regression, Ruff/mypy, packaging and
> gated MariaDB CI; record human Windows/Kali/recovery field work as
> NOT RUN unless directly observed. Add a small PR linked to #123,
> with measured results and remaining blockers. Do not check off
> PX-004 or the roadmap merely because CI passes.
>
> If advancing another P1/P2 roadmap ID instead, first check source
> parity with #170 (PX-104 paging), #171/#174 (PX-304 local
> inventory and exact OSV matching) and #175 (PX-203 saved evidence tiers)
> to avoid duplicating those partial implementations.

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
