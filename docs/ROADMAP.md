# PenX — Product and Engineering Roadmap (Codex-ready)

**Status:** proposal/implementation tracker, with pending acceptance noted below. **Release baseline:** published PenX v0.6.0 (2 November 2026); current `main` is newer than the released binaries.
**Audience:** maintainers and Codex implementation agents. **Scope:** Windows 10/11, Kali Linux, Debian, Ubuntu; defensive and authorized assessments only.
**Implementation protocol:** [CODEX_EXECUTION.md](CODEX_EXECUTION.md), repository [AGENTS.md](../AGENTS.md).
**Not a release promise.** Version targets, estimates and performance criteria below are proposals, subject to benchmark and operator validation.

## Implementation snapshot — 4 November 2026

This table describes **merged source**, not the separately published v0.6.0 binaries or human field sign-off. The 4 November source snapshot now includes [#168](https://github.com/spk-c/PenX/pull/168) and [#169](https://github.com/spk-c/PenX/pull/169) (MariaDB lexical SQL diagnostics), [#170](https://github.com/spk-c/PenX/pull/170) (bounded local session history) and [#171](https://github.com/spk-c/PenX/pull/171) (offline SBOM inventory), through merge commit `ef20dcc3e12f6289faa2ce0209ec535e1e9855d3`. All applicable PR checks for those slices passed; hosted Windows jobs were skipped for some branches but additional standalone Windows offline suites passed. **No real target scan, live MariaDB restore, model accuracy measurement, signed release or independent Windows/Kali field sign-off is implied.**

| Roadmap ID | Implemented and merged | Remaining acceptance (not signed off) |
| --- | --- | --- |
| **PX-001** | [#133](https://github.com/spk-c/PenX/pull/133): additional Kali field worksheet and validator | Actual Windows/Npcap, Kali, upgrade/rollback, large-report and DB restore **human field evidence** |
| **PX-002** | [#132](https://github.com/spk-c/PenX/pull/132), [#145](https://github.com/spk-c/PenX/pull/145): scanner reason taxonomy and post-wait errors; historical v1/v2/v3 metadata strict-version parsing with negative/downgrade fixtures | Remaining real-adapter failure matrix, live TUI parity, field acceptance of legacy stored databases; no full milestone sign-off |
| **PX-003** | [#124–#131](https://github.com/spk-c/PenX/pulls?q=is%3Apr+is%3Amerged+PX-003), [#143](https://github.com/spk-c/PenX/pull/143), [#144](https://github.com/spk-c/PenX/pull/144): negative corpus, 1,000-finding report parity, hash-bound retained UTF-8 source. Opt-in original subprocess stdout-byte capture is now bound to eligible **headless report** adapter identities and version-3 metadata with a report SHA/filename manifest; offline three-way verification available (see `docs/PX003_STDOUT_BYTE_CAPTURE.md`) | Opt-in interactive scanner-menu capture and read-only SQLite session source verification added (see `docs/PX003_INTERACTIVE_SESSION_PROVENANCE.md`); Explicit loopback-only MariaDB READ ONLY session verification added (see `docs/PX003_MARIADB_READONLY.md`); real user DB/least-privilege field acceptance, transformed/mixed adapters, remaining negatives and human PDF/Kali/Windows sign-off still open |
| **PX-004** | [#135](https://github.com/spk-c/PenX/pull/135), [#153](https://github.com/spk-c/PenX/pull/153), [#154](https://github.com/spk-c/PenX/pull/154), [#157](https://github.com/spk-c/PenX/pull/157), [#160](https://github.com/spk-c/PenX/pull/160), [#161](https://github.com/spk-c/PenX/pull/161): verified SQLite backup/preview/restore and MariaDB read-only scratch comparison. [#163](https://github.com/spk-c/PenX/pull/163) adds fail-closed external WAL/journal guards; [#164](https://github.com/spk-c/PenX/pull/164) adds strict bounded duplicate-free SQLite manifests, source-schema matching and symlink rejection; [#168](https://github.com/spk-c/PenX/pull/168) and [#169](https://github.com/spk-c/PenX/pull/169) add non-executing MariaDB dump red-flag/lexical EOF inspection and disposable native-dump CI coverage | **Partial:** no production-safe MariaDB restore, verified historical dump SQL semantics, cross-schema atomicity, rollback/maintenance isolation or external operator recovery sign-off. Real user DBs are not tested |
| **PX-005** | [#136](https://github.com/spk-c/PenX/pull/136): CycloneDX SBOM, deterministic build manifest, offline asset verification | No signing/attestation claims; exercise on the next authorized tagged release and independent Windows field acceptance |
| **PX-101** | [#134](https://github.com/spk-c/PenX/pull/134), [#141](https://github.com/spk-c/PenX/pull/141), [#142](https://github.com/spk-c/PenX/pull/142), [#162](https://github.com/spk-c/PenX/pull/162): explicit approved/candidate registry, confirmed approval/revocation CLI, opt-in constrained project-bound HTTP/DNS/TLS/httpx/passive scans and per-call storage checks | **Partial:** unaudited external adapters remain blocked, no project batch jobs or real operator field acceptance |
| **PX-103** | [#137](https://github.com/spk-c/PenX/pull/137): TTY detection, no-color/plain mode, width-aware rendering helpers | Scanner live-progress integration, full wrapping and Windows/Linux keyboard/TTY field matrix |
| **PX-104** | [#170](https://github.com/spk-c/PenX/pull/170): explicit read-only SQLite history keyset pages (1–100 headers), date/target/status filters and default target redaction | **Partial:** no combined project/scanner/evidence views, MariaDB history parity, durable batch jobs or owner field acceptance |
| **PX-304** | [#171](https://github.com/spk-c/PenX/pull/171): strict local-only CycloneDX JSON 1.5/1.6 and SPDX JSON 2.3 import, bounded exact PyPI/npm purl identity counts and default redaction | **Partial:** no OSV/advisory matching, vendor-backport adjudication or field acceptance; **no vulnerability verdict** |
| **PX-401** | [#146](https://github.com/spk-c/PenX/pull/146): noninteractive local `llm-info` model capability diagnostics, opt-in probe, redacted JSON | Provider identity, context retention and cancellation still need local NInfer/Strata/llama.cpp/Ollama field testing |
| **PX-403** | [#165](https://github.com/spk-c/PenX/pull/165): versioned deterministic offline fixture benchmark, exact source-anchor scoring, bounded/redacted metrics, refusal/timeout/invalid-JSON cases | **Partial:** no actual model inference, loaded-model proof, independently reviewed dataset, live precision/recall or operator sign-off |
| **PX-501** | [#166](https://github.com/spk-c/PenX/pull/166): hardened manual-only authorized scan/SARIF Actions example, pinned actions, no persisted checkout token and hash-locked dependencies with offline contract tests | **Partial:** no target-licensed end-to-end workflow field proof or independently verified SARIF upload in a configured repository |

## Acceptance matrix — all 36 roadmap IDs (4 November 2026)

**Every row below is an acceptance status, not a claim of absent code.**
Twelve IDs have documented merged source/baseline slices, ten have explicit
dependency blockers and the remaining fourteen have no documented milestone
acceptance. Related pre-existing PenX functionality may exist; it does not
by itself satisfy the new milestone's tests, safeguards and field criteria.
**No complete 36-item roadmap or v1.0 field certification is claimed.**

| ID | Status | Next unmet gate |
| --- | --- | --- |
| PX-001 | Partial source | Field matrix: human Windows/Npcap/Kali and backup acceptance |
| PX-002 | Partial source | Remaining real-adapter taxonomy, legacy TUI/DB parity |
| PX-003 | Partial source | External provenance and multi-adapter/PDF field sign-off |
| PX-004 | Partial source | No SQL provenance, historical rows, maintenance/rollback or user DB restore |
| PX-005 | Partial source | SBOM/manifests merged; tagged release verification/signing pending |
| PX-101 | Partial source | Blocked scanner adapter audits, grants, owner field validation |
| PX-102 | Blocked/dependent | Do not auto-resume work until recovery + scope gates |
| PX-103 | Partial source | TTY progress, wrapping and human keyboard testing |
| PX-104 | Partial source | SQLite redacted paging merged; project/MariaDB/evidence filters remain |
| PX-105 | Blocked/dependent | Requires PX-101/102 acceptance and explicit opt-in |
| PX-106 | Blocked/dependent | Depends on safely approved recurring work and history |
| PX-201 | Not accepted | Human lifecycle/audit trail not accepted |
| PX-202 | Blocked/dependent | Dependent on accepted finding lifecycle |
| PX-203 | Not accepted | Quality vector and cross-format parity not accepted |
| PX-204 | Blocked/dependent | Dependent human remediation audit workflow |
| PX-205 | Blocked/dependent | Depends on reviewed evidence quality model |
| PX-206 | Blocked/dependent | Depends on stable human finding identity and review |
| PX-301 | Not accepted | Expanded HTTP policy fixture/field acceptance pending |
| PX-302 | Not accepted | Certificate hygiene fixture/trust acceptance pending |
| PX-303 | Not accepted | DNS/mail posture parser and resolver fixture matrix pending |
| PX-304 | Partial source | Local CycloneDX/SPDX inventory merged; advisory/backport scoring absent |
| PX-305 | Not accepted | Local IaC/config scan limits and fixture safety pending |
| PX-306 | Not accepted | Third-party adapter SDK and isolation pending |
| PX-307 | Not accepted | Template policy/capability and safe scope audit pending |
| PX-401 | Partial source | Local LLM diagnostics merged, actual-provider field proof pending |
| PX-402 | Not accepted | Model-to-source contradiction checks not accepted |
| PX-403 | Partial source | Synthetic offline scorer merged; live model accuracy unmeasured |
| PX-404 | Blocked/dependent | Second-pass disagreement dependent on source grounding |
| PX-405 | Not accepted | Provider freshness/applicability proof pending |
| PX-501 | Partial source | Manual-only SARIF workflow source merged, end-to-end field proof absent |
| PX-502 | Not accepted | Safe bundle import/export acceptance pending |
| PX-503 | Blocked/dependent | Depends on accepted PX-104/201 and localhost controls |
| PX-504 | Not accepted | Native ARM64 runtime and artifact field matrix pending |
| PX-505 | Blocked/dependent | Blocked on opted-in recurring and delta notifications |
| PX-506 | Not accepted | Comparable performance budget and sanitized baselines pending |
| PX-507 | Not accepted | Package manager installation/signing/owner sign-off pending |

The [#138 CI repair](https://github.com/spk-c/PenX/pull/138) switched transiently failing Kali mirror installs to a bounded signed-repository CDN fallback. This is infrastructure work, not a roadmap item or a new release.

**Next dependency gate:** PX-004 production-safe MariaDB restore design and independent SQLite/WAL field recovery, PX-001/PX-003 operator provenance checks, and [PX-101 scope audit #140](https://github.com/spk-c/PenX/issues/140) for each blocked external adapter. Keep unaudited scanners disabled in project mode. **Do not start PX-102 automatic resume** until applicable grant, cancellation and recovery acceptance is demonstrated. No milestone is completed by a green PR alone.

## 1. Product direction

Evolve PenX from a *single-target terminal reconnaissance/assessment application* into a trustworthy, offline-capable **assessment workspace**: scope-approved assets, resumable collection, traceable findings, human review, comparative risk, and repeatable reporting. Keep the CLI as the stable core; optional TUI or localhost UI must not weaken the headless or safety contracts.

### Existing functionality — extend rather than rebuild

| Already implemented on v0.6.0 | Roadmap extension |
| --- | --- |
| 12 built-in scanner adapters + separate endpoint mapping | Stronger schema/adapter SDK, carefully scoped read-only checks |
| ScanPlan: profiles, typed settings, deadlines, budget, controlled concurrency, dependency ordering and cancellation | Persisted job queue, explicit projects/scopes and opt-in recurring runs |
| Interactive menu, guided scan, headless CLI, dry-run, JSON/SARIF, SARIF policy exit codes | Accessible TUI, batch workspace and CI-friendly comparisons |
| Evidence records, raw-artifact references, fingerprints, scan diff, corrections, review | Finding lifecycle, stable cross-run triage and evidence quality scores |
| SQLite, optional MariaDB, schema migration and crash/atomic report safeguards | Migration-tested workspace database, encrypted secret references and verified backups |
| Local compatible LLM, optional bounded review-scan, strict structured review, safe loopback restriction | Repeatable evaluation harness, grounded model disagreement and capability diagnostics |
| NVD/OSV/GitHub advisories, CVSS/EPSS/CISA KEV, package/distro research | Explainable applicability, freshness, vendor fix status and false-positive feedback |
| Windows installer/ZIP, Linux amd64 DEB/TAR, tests and hash files | Full field sign-off, provenance/SBOM, ARM64 release acceptance |

**Do not implement an item until Codex checks the current source, tests and open PRs for existing equivalent behavior.** Most tasks should be enhancements of current modules, not parallel replacements.

## 2. Ground rules and quality gates

1. **Authorization and scope:** Never scan arbitrary Internet targets, derive new in-scope domains/IPs automatically, bypass consent, or run active checks in passive mode. Network/integration tests use owned loopback fixtures or explicit owner authorization.
2. **No exploit automation:** No exploit payload delivery, credential attacks, stealth/evasion, persistence, unattended exploitation, or autonomous vulnerability exploitation. Finding verification is read-only/evidence-based or requires explicit human approval of a separately reviewed test.
3. **Evidence before verdict:** Preserve COMPLETE/PARTIAL/FAILED, observed-vs-inferred provenance and coverage. Unknown is not safe; banner/CVE matches are not proof. Human corrections must remain separate from source evidence.
4. **Local-first/privacy:** No surprise cloud uploads or arbitrary model-driven URL fetching. Keep secrets out of profiles, logs, SARIF and model context; network calls explicit and bounded. Optional localhost UI binds 127.0.0.1 only by default.
5. **Compatibility:** Preserve CLI commands, config precedence, historical scan records, existing JSON/SARIF schemas and v0.6.0 distributions. Add schema versions/migrations instead of silently changing previous fields.
6. **Resource budgets:** Bound data size, concurrency, timeout, retries, scan rate, raw artifacts and memory. Cancelling a scan must clean up scanner descendant processes without falsely committing a finished assessment.
7. **Tests before delivery:** Each PR adds offline deterministic tests, negative/security cases and targeted integration/packaging smoke tests; do not treat a green mock test as human field sign-off.
8. **Small PRs:** One vertical feature per PR (aim roughly 200–800 changed code lines, split if larger), with a design note, rollback and updated docs. No opaque “fix everything” branches.
9. **No silent production state changes:** Make migrations transactional and backups operator-approved; no overwriting existing report/session files or altering released binaries.
10. **Progress:** Codex pushes the work branch after each complete slice and updates the related roadmap checkbox or PR description with test evidence. Merge only when checks pass.

## 3. Priority model and dependency order

- **P0 — integrity/safety:** A misleading completion status, data loss, out-of-scope execution, missing evidence or unverifiable release blocks progress.
- **P1 — user value:** Enables a practical new workflow, particularly repeatable audits and reduction of manual steps.
- **P2 — quality/coverage:** Better evidence, explainable risk or defensively broadened coverage.
- **P3 — optional/long-term:** Advanced UI, teams, alternative platforms and ecosystem polishing.
- Sizes: **S** ≈ 1 focused PR, **M** ≈ 2–3 PRs, **L** ≈ design + multiple iterations. These are relative effort classes, not time promises.

**Recommended order:** P0 field/test foundation → scope/workspace → resumable jobs → finding lifecycle → deep, conservative assessments → AI evaluation → optional interfaces and external integrations.

## 4. Milestone A — v0.6.x hardening and trust (P0)

### PX-001 — Field acceptance evidence runner (P0, M)
**Goal:** Convert remaining Windows/Npcap, installer upgrade/rollback, SQLite/MariaDB restore, large PDF/HTML visual and model-failure field gates into reproducible operator worksheets; keep human sign-off separate.
**Implementation:** Extend scripts/collect_refactor_field_evidence.ps1, scripts/validate_field_acceptance.py and docs/FIELD_ACCEPTANCE.md; support Windows and Kali environments, immutable build hash and sanitized output.
**Done:** Every gate has status PASS/FAIL/BLOCKED/NOT RUN, OS/arch, binary SHA, steps, expected/actual, evidence location, independent reviewer. Missing proof never produces sign-off. No production network target or database touched automatically.
**Tests:** Synthetic worksheets, malformed/duplicate entries, failed restores, install/uninstall with disposable VM only.

### PX-002 — Canonical scanner-result and error taxonomy (P0, M)
**Goal:** Consistent adapter diagnostics across TUI, CLI, JSON, SARIF, history and AI.
**Implementation:** Evolve domain/scan_models.py, domain/scan_diagnostics.py, application/scanner_execution.py and scanners/process_runner.py with a versioned machine-readable error code (missing dependency, timeout, cancelled, truncated, scope denied, partial, parse invalid).
**Done:** Every terminal adapter event has stable ID/status/duration/reason; no FAILED row with evidence=true; migration preserves old readers. No blanket exception swallowing.
**Tests:** Unit/fixture matrix for all 12 adapters, cancellation and timeouts, malformed/truncated responses, old metadata round-trip.

### PX-003 — Golden corpus and adversarial fixture harness (P0, M)
**Goal:** Prevent false positives and parser regressions as scanners evolve.
**Implementation:** Build sanitized fixture packs for each adapter (success, absent evidence, contradictory responses, HTTP 429, bad encodings, long output, nonexistent tools), with read-only provenance and expected schema snapshots.
**Done:** Offline tests exercise real parsers without network; per-format outcome parity and source-quote traceability enforced in CI; no live scanner data or customer secrets committed.
**Tests:** pytest/unittest fixture runner integrated with offline_tests.py; record baseline and deltas.

### PX-004 — Verified backup/restore and migration dry-run (P0, M)
**Goal:** Make local history and evidence survivable through upgrades, while preserving SQLite WAL and optional MariaDB correctness.
**Implementation:** storage/schema_migrations.py, storage/session_repository.py, app_paths.py; add manifest/version/size/hash for sanitized export, test-only restore preview, transactional recovery and explicit user-approved restore.
**Done:** Crash/interrupt cannot make an unverified backup appear valid; no in-place overwrite without backup; legacy history round-trips and rollback on failure.
**Tests:** v0.5/v0.6 fixtures, simulated disk full/process kill/duplicate rows, isolated MariaDB integration.

### PX-005 — Release supply-chain and artifact transparency baseline (P0, S/M)
**Goal:** Make it easy to verify a build and its dependency inventory.
**Implementation:** Keep SHA256SUMS and existing tag gates; add CycloneDX/SPDX SBOM for Python/build runtime, dependency provenance/attestations where supported, and offline hash/manifest verification utility.
**Done:** Hashes, tag, exact commit, platform, dependency inventory and build workflow recorded; no claims of Authenticode/sigstore signing unless actual keys/attestations are verified.
**Tests:** Tampered asset/hash refusal, deterministic manifest contracts, distribution smoke; independent Windows field sign-off remains separate.

## 5. Milestone B — v0.7.0 workspace and operator UX (P1)

### PX-101 — Strict project and authorized asset registry (P1, M)
**Goal:** Allow named projects, approved target lists and tags instead of repeatedly entering isolated targets.
**Implementation:** New domain/project_scope.py, storage/project_repository.py, application/project_service.py and CLI project commands. Store target canonicalization, explicit approval timestamp, optional per-asset max rate/budget and expiry.
**Done:** Only exact, explicitly approved targets can run. CIDR expansion is bounded and previewed; discovered subdomains are *candidates*, never automatically authorized. No wildcard/regex scope escapes, SSRF or internal network expansion.
**Tests:** IDN/IPv6/ports, scope boundary/property tests, duplicates, approval expiry, unexpected redirects.

### PX-102 — Persistent scan-job state machine (P1, L; depends on PX-002, PX-004, PX-101)
**Goal:** Queue, pause/cancel, inspect and safely resume interrupted collections.
**Implementation:** application/scan_planner.py, application/scan_recovery.py and storage/job_repository.py. States: CREATED → APPROVED → RUNNING → COMPLETE/PARTIAL/FAILED/CANCELLED; journal per-adapter results and versioned plan hashes.
**Done:** Restart never silently repeats a consent-gated active adapter; resume requires plan hash/scope revalidation and explicit approval where appropriate; partial outcomes remain partial.
**Tests:** power-loss/kill after each transition, concurrent workers, locked database, cancellations and duplicate submit idempotence.

### PX-103 — Modern accessible terminal UI (P1, M)
**Goal:** Make existing interactive CLI clearer without forcing a GUI or changing headless output.
**Implementation:** cli/console_ui.py, cli/scanner_menu.py, cli/assessment_ui.py, cli/terminal_theme.py; optional minimal terminal rendering library only after dependency review.
**Features:** live progress by scanner, elapsed/budget, evidence count, cancelled/partial status, keyboard-only navigation, screen-reader-friendly plain mode, no-color and redirected-TTY detection.
**Done:** Works on Windows Terminal, PowerShell and Linux tty/SSH, including 80-column terminals; Ctrl+C/Esc semantics correct; ANSI never leaks into JSON/SARIF.
**Tests:** terminal snapshots, noninteractive stdout/stderr contracts, keyboard/cancel golden cases.

### PX-104 — Saved workspace views and batch summaries (P1, M; depends on PX-101/102)
**Goal:** Filter projects/assessments by asset, date, evidence status, scanner, profile and confidence.
**Implementation:** storage/session_repository.py, application/scan_trends.py and reporting/report_view.py; incremental pagination and bounded indexed queries.
**Done:** Large histories can be searched without reading all raw artifacts; exports remain deterministic; redaction prevents accidental target/secret disclosure.
**Tests:** 10k synthetic sessions, query worst-case memory, stable ordering, injection/Unicode cases.

### PX-105 — Explicitly opt-in recurring scans (P1, L; depends on PX-101/102)
**Goal:** Repeat authorized profiles on schedules with change summaries, *without* autonomous target discovery.
**Implementation:** schedule configuration with OS-native Windows Task Scheduler/systemd timers or a single-process scheduler; no privileged/background service by default.
**Done:** Scheduling disabled by default; every job has unexpired scope approval, rate cap, concurrency budget, misfire policy and audit log; reauthorization required after scope/profile changes; dry-run shows exact targets.
**Tests:** daylight-saving time, failed runs/backoff, overlap prevention, opt-out, expired authorization. No public targets in CI.

### PX-106 — Scan-delta triage and baseline alerts (P1, M; depends on PX-104/105)
**Goal:** Only notify on meaningful, reproducible changes, not every Nmap banner variation.
**Implementation:** Extend application/scan_trends.py and domain/finding_identity.py; baseline pinning, coverage-aware missing-vs-resolved distinction, optional local notification output.
**Done:** “Resolved” requires comparable coverage; missing/unavailable scanners produce UNKNOWN; notifications never leak private targets by default; no messaging/network destinations enabled automatically.
**Tests:** fixtures for changed ports, response order, URL case, missing scanners, new/reappeared findings.

## 6. Milestone C — v0.7.x evidence, remediation and reporting (P1/P2)

### PX-201 — Finding lifecycle and triage states (P1, M; depends on PX-004)
**Goal:** HUMAN triage status per finding: NEW, INVESTIGATING, CONFIRMED, FALSE_POSITIVE, ACCEPTED_RISK, FIXED, REOPENED.
**Implementation:** domain/finding_policy.py, domain/corrections.py, storage/correction_repository.py, CLI/history_dialog.py; add user, rationale, timestamps and optional expiry to a separate audit trail.
**Done:** Scanner output cannot silently change a human conclusion; expired exceptions become review-needed; raw evidence immutable; rejected/unknown AI cannot mark fixed.
**Tests:** versioned migrations, edit permissions, state transitions, duplicate cases and historical export compatibility.

### PX-202 — Stable cross-run correlation and suppression rules (P1, M; depends on PX-201)
**Goal:** Reconcile findings across repeats and tools without hiding evidence.
**Implementation:** Extend domain/finding_identity.py, reporting/finding_trace.py and application/scan_trends.py. Separate identity from confidence, rule engine from individual evidence.
**Done:** Only explicit, bounded project-scoped suppression with reason/expiry; collisions/ambiguity report UNKNOWN instead of accidental merge; suppressions are visible in all exports.
**Tests:** canonical URL path/query case, port/service changes, renames, duplicate IDs, different asset scopes.

### PX-203 — Evidence confidence and quality score (P1, M; depends on PX-002/003)
**Goal:** Make the difference between scanner observation, verified applicability and model inference easy to understand.
**Implementation:** domain/evidence.py, domain/scan_models.py and reporting/machine_reports.py with an explainable evidence-quality vector: source identity, freshness, parse confidence, independent corroboration, and coverage.
**Done:** No arbitrary single “probability of exploitation”; unknown freshness and unavailable sources lower confidence; evidence score never upgrades AI text to a fact.
**Tests:** partial/contradictory/missing evidence and source-provenance cases; parity across JSON/SARIF/HTML/PDF.

### PX-204 — Remediation workspace with verification history (P1, M; depends on PX-201/202)
**Goal:** Let an operator record mitigation, owner, review-by date, source and follow-up verification.
**Implementation:** application/assessment_service.py, storage/session_repository.py and CLI/history; importable safe Markdown/JSON remediation tasks.
**Done:** No auto-changing a remote system, no auto-exploiting a finding; remediation becomes VERIFIED only through explicit evidence or operator sign-off, not an absent scan finding.
**Tests:** before/after coverage, manual acceptance signatures, rollback and reappearance.

### PX-205 — Explainable risk priority dashboard (P2, M; depends on PX-203)
**Goal:** Show why an issue is prioritized without inventing vulnerability verification.
**Implementation:** intelligence/cve_priority.py, intelligence/vendor_status.py, application/risk_assessment.py; rank from documented CVSS, FIRST EPSS, CISA KEV, observed exposure and vendor status. Avoid simplistic additive scores and unknown-as-zero.
**Done:** Displays score components, timestamp/source, exclusions, uncertainty and operator overrides. Risk never implies confirmed exploitability.
**Tests:** missing EPSS/KEV, fixed distro packages, stale caches, input poisoning, stability under reorder.

### PX-206 — Reviewable report templates and side-by-side diffs (P2, M; depends on PX-202)
**Goal:** Executive summary, technical evidence appendix, changes since baseline, audit sign-off and machine-readable contracts.
**Implementation:** reporting/report_design.py, report_batch.py, terminal_pdf.py and machine_reports.py. Keep HTML self-contained/offline; default safe escaping.
**Done:** Templates show coverage/unknowns, reviewer decisions and redaction level; long PDFs page correctly; no unsanitized HTML/Markdown injection.
**Tests:** 1/10/1000 finding layout, PDF extractability, invalid UTF-8, 80-column CLI, report parity.

## 7. Milestone D — v0.8.0 defensive coverage (P2)

All additions must use explicit authorization, fixed bounded probes and conservative interpretation. New scanner menu entries change the 12-adapter baseline and require a versioned migration/docs/CI review; an offline parser/module can be delivered first.

### PX-301 — Expanded HTTP configuration audit (P2, M)
**Scope:** Existing headers responses: HSTS, CSP, CORS, cookies/SameSite/Secure/HttpOnly, cache and redirect configuration. No login fuzzing or endpoint brute-force.
**Done:** Evidence quotes and source URL for each observation; false positive exceptions for application-specific cases; redirects stay in approved scope.
**Tests:** Local HTTP fixtures for proxy headers, multi-cookie cases, duplicated/contradictory headers and 3xx chains.
**Touches:** scanners/native_web_scanners.py, application/scanner_observations.py, reporting/scan_coverage.py.

### PX-302 — TLS certificate/trust hygiene checks (P2, M)
**Scope:** Verify expiry window, hostname mismatch, trusted-chain status when observable, protocol/cipher information when safely available; no claim of exhaustive TLS grading.
**Done:** Separate observed facts from platform trust-store assumptions and negotiated-client details; bound handshakes and record certificate chain.
**Tests:** Ephemeral loopback TLS cert fixtures, expiry/hostname mismatch, handshake error and timeouts.
**Touches:** scanners/native_web_scanners.py and domain/evidence.py.

### PX-303 — DNS/email-domain posture report (P2, M)
**Scope:** Read-only parsing of MX, SPF, DMARC, CAA, DKIM only with explicitly known selectors, MTA-STS records and DNSSEC signal availability; do not crawl/guess DKIM selectors.
**Done:** Differentiates missing data, configured-but-unverified and observed misconfiguration; no outbound email and no spoofing tests.
**Tests:** Local mock resolver zone fixtures, wildcard/IDN, records split across TXT strings, NXDOMAIN, DNS failures.
**Touches:** scanners/native_web_scanners.py, scanners/passive_recon.py.

### PX-304 — Offline SBOM import and package exposure analysis (P2, M)
**Scope:** Read locally provided CycloneDX/SPDX inventory and reconcile OSV/advisories with exact package/version/ecosystem and distro backports. Never upload an SBOM silently.
**Done:** Detect file size/schema limits and duplicate records; ambiguous versions remain candidates; local processing works without AI.
**Tests:** Golden SBOMs with false matches, malformed input, vendor backports and no-network fixtures.
**Touches:** intelligence/package_inventory.py, intelligence/vendor_status.py, intelligence/cve_engine.py.

### PX-305 — Local configuration/IaC checks (P2, L)
**Scope:** Optional offline linting of user-supplied nginx/Apache/TLS policies, Docker Compose and selected infrastructure-as-code files, through safe parsers. No shell execution of untrusted configuration and no implicit cloud credentials.
**Done:** Read-only, schema/version-limited, deterministic rule IDs/evidence line references, deliberate false-positive controls.
**Tests:** Fixture corpus, path traversal, YAML aliases/billion laughs, giant files, unknown keys.
**Touches:** New scanners/local_config.py, application/preflight.py and reporting/machine_reports.py.

### PX-306 — Hardened third-party adapter contract / SDK (P2, L; depends on PX-002/003)
**Scope:** Registry declaration for command identity, capabilities, consent requirement, platform availability, timeouts, parser and artifact budgets; no user-supplied shell expressions or arbitrary model-generated commands.
**Done:** Declarative opt-in adapter installation with hash/provenance and sandboxed or isolated process invocation where possible; built-ins keep stable IDs; disabled by default if verification fails.
**Tests:** Untrusted adapter manifests, invalid paths/arguments, wrong architecture, cancellation and output limits.
**Touches:** scanners/registry.py, scanners/process_runner.py, domain/scanner_configuration.py.

### PX-307 — Nuclei template policy manager (P2, S/M)
**Scope:** Explicit template provenance, pinned version/hash, severity/scope filters, request limits and review before any template set changes.
**Done:** Safe documented defaults, no automatic arbitrary Internet template downloads/execution; templates with intrusive actions require explicit separate consent or are rejected.
**Tests:** Tampered templates/manifest, path traversal, malicious metadata, unpinned revision and runtime budget.
**Touches:** scanners/tools.py, application/preflight.py, domain/scan_plan.py.

## 8. Milestone E — v0.8.x local intelligence and quality (P1/P2)

### PX-401 — Model capability handshake and preflight (P1, S/M)
**Scope:** Upgrade existing --llm-setup to report context limit (only if provider exposes it), JSON schema response support, streaming, cancellation and actual model ID. No model download or cloud fallback.
**Done:** Distinguish unsupported/unknown vs supported; loopback or explicitly approved configured local endpoint; no probe of scan targets.
**Tests:** Mock OpenAI-compatible servers, 400/404/429, malformed model lists and model mismatch.

### PX-402 — Source-grounded review with contradiction check (P1, M)
**Scope:** Require each local-AI finding to reference bounded immutable evidence anchors; detect claims unsupported by source or contradicted by scanner status.
**Done:** Unsupported findings flagged DRAFT/UNVERIFIED and cannot inflate severity; every claim links to exact scan/artifact hash; failures do not rewrite existing saved evidence.
**Tests:** Fabricated CVE/port/version, prompt injection in HTTP banners, conflicting adapters, missing anchors.
**Touches:** analysis/structured_scan_evidence.py, analysis/assessment_quality.py, domain/evidence.py.

### PX-403 — Reproducible AI assessment evaluation harness (P1, M)
**Scope:** Add a curated local fixture benchmark to measure hallucination, claim/evidence alignment, false positives and structured output validity across Qwen/other compatible local models.
**Done:** Offline baseline with zero-model fixtures; optional real-model runs require user-provided endpoint and save sanitized machine-readable metrics. Do not manufacture accuracy percentages.
**Tests:** Prompt/version pinning, deterministic scoring, refusal/timeout/JSON errors, no external-data leaks.
**Touches:** tests/fixtures, scripts/benchmark_ai_assessment.py (proposed), analysis/*.

### PX-404 — Optional second-pass model disagreement review (P2, M; depends on PX-402/403)
**Scope:** With explicit operator opt-in, compare two local draft interpretations of identical evidence using the same schema/budget.
**Done:** Outputs agree/disagree/insufficient, never majority-vote “verified”; bounded total token/time cost, no hidden cloud fallback, and human approval.
**Tests:** Contradictory, empty, non-JSON, budget-exhausted and one-model-failed fixtures.

### PX-405 — Provider cache freshness and applicability diagnostics (P2, S/M)
**Scope:** Expose source freshness, advisory update time, distro fix applicability, cache TTL, provider failures and coverage gaps in reports.
**Done:** Users can distinguish “no match,” “provider unavailable,” “candidate pre-fix,” and “vendor patched”; stale reference data does not silently elevate findings.
**Tests:** Partial NVD/OSV/KEV/EPSS inputs, malformed JSON, stale cache, upstream rate limit, vendor backport cases.
**Touches:** intelligence/cve_engine.py, nvd_disk_cache.py, source_verification.py.

## 9. Milestone F — v0.9.x integrations, packaging and optional UI (P2/P3)

### PX-501 — CI integration templates and SARIF publishing example (P2, S)
**Scope:** Document pinned GitHub Actions usage and optional SARIF upload from existing headless scan; explicit target authorization, opt-in permissions and secret-free fixture workflow.
**Done:** Examples cannot run against unrelated hosts by default, do not imply SARIF upload is always available, and leave existing exit-code policy unchanged.
**Tests:** GitHub workflow static validator and safe loopback integration smoke.

### PX-502 — Interoperable import/export bundles (P2, M)
**Scope:** Versioned offline exchange of approved assessment findings, evidence anchors, machine reports and corrections, with integrity manifest and redaction.
**Done:** Round-trip compatible, no path traversal/zip bombs/duplicate-key bypass, separate human annotations, no automatic merging of ambiguous findings.
**Tests:** Golden export/import, corrupt archive, malicious paths, schema downgrade, PII redaction.

### PX-503 — Local-only read-only report viewer (P3, L; depends on PX-104/201)
**Scope:** Optional browser interface bound to 127.0.0.1, ideally serving generated static reports or read-only indexed views; no remote listening, scanning or admin endpoint by default.
**Done:** Explicit launch, authenticated session if state-changing features are later proposed, CSP/CSRF/XSS safeguards and no secrets displayed; CLI remains first-class.
**Tests:** Port binding, cross-origin access denial, HTML escaping and shutdown/cleanup.
**Note:** A dashboard is optional. Do not block core CLI progress on a GUI.

### PX-504 — Linux ARM64 build and field matrix (P3, L)
**Scope:** Native ARM64 build on actual compatible runner/VM, hashed dependencies, Linux portable + optional arm64 DEB; no cross-compiled PyInstaller assumption.
**Done:** Binary startup, scanner dependency discovery, schema/export parity and one owner-controlled ARM64 runtime smoke test before publishing.
**Tests:** CI native packaging, checksum verifier, ABI/glibc comparison, isolated Kali/Debian arm64 fixture when available.

### PX-505 — Optional notifications and webhooks (P3, M; depends on PX-105/106)
**Scope:** Event-driven **operator-configured** local logs or outbound webhook integrations for coverage changes and reviewed findings. Disabled by default.
**Done:** No target disclosure without explicit opt-in; destination allowlist/SSRF controls, redaction, bounded retries and deletion/audit controls.
**Tests:** Local loopback sink, secret masking, retry storms, offline failure and disable behavior.

### PX-506 — Performance and dependency budget dashboard (P2, M)
**Scope:** Add repeatable CLI/import latency, memory peak, scanner dispatch budget, report generation, package size and test runtime tracking.
**Done:** Historical baselines show stable comparable hardware/fixture info; regression thresholds recorded before optimizations; benchmark artifacts sanitized.
**Tests:** Multi-platform synthetic benchmark runs, RSS limits, long report stress and fail-open benchmark outage (without hiding CI failures).

### PX-507 — Trusted distribution integrations (P3, M)
**Scope:** Validate actual WinGet/Scoop installation, upgrade/uninstall state retention and signed installer possibilities; separately plan Python package Trusted Publishing only if ownership and maintenance are agreed.
**Done:** No public-registry claim before accepted publication; no signing claim until successful signature verification; approved package identities and migration documentation.
**Tests:** Disposable Windows VM first-install + upgrade/rollback + uninstall, checksum verification and cross-version data preservation.

## 10. Milestones and launch criteria

| Tentative release | Minimum outcome | Exit criteria |
| --- | --- | --- |
| **v0.6.1 / v0.6.x** | PX-001–005 | Integrity contracts green; remaining manual acceptance explicitly documented, not misrepresented |
| **v0.7.0** | PX-101–104, core PX-201 | Scoped projects, persisted collection jobs, reliable CLI/TUI and triage without regressions |
| **v0.7.x** | PX-105/106, PX-202–206 | Opt-in recurring scans, meaningful comparison, lifecycle, confidence and useful report templates |
| **v0.8.0** | PX-301–307, based on capacity | Conservative expanded defensive analysis with reproducible parser fixtures |
| **v0.8.x** | PX-401–405 | Grounded local AI claims and measurable evaluation quality |
| **v0.9.x** | PX-501–507 as prioritized | Optional integrations, read-only UI, verifiable distribution and portability |
| **v1.0** | Only after independent validation | Explicit Windows/Linux field sign-off, stable contracts, upgrade/restore rehearsals, documented support and no P0 safety/data-integrity defects |

Do not tie release tags to a fixed calendar. Any phase can be re-ordered when an actual defect or verified operator need has higher value.

## 11. Current near-term Codex queue (updated 4 November 2026)

The original PR-A/B/C/D preparatory slices have already been merged: PX-003 ([#124–#131](https://github.com/spk-c/PenX/pulls?q=is%3Apr+PX-003)), PX-002 ([#132](https://github.com/spk-c/PenX/pull/132)), PX-001 ([#133](https://github.com/spk-c/PenX/pull/133)) and PX-101 ([#134](https://github.com/spk-c/PenX/pull/134)). **Do not recreate these starting tasks.** The following are remaining vertical slices, not automatic permissions to scan or publish.

1. **PX-101 dispatch follow-up [#140](https://github.com/spk-c/PenX/issues/140) (P1, required before PX-102):** continue adapter-by-adapter review of the opt-in safe subset (HTTP headers, DNS, TLS, httpx, passive — httpx approved 2026-11-04 with the bounded single-origin, no-redirect, one-request contract). Test rate/redirect/revocation behavior and approve further adapters only with bounded no-redirect, no-target-expansion contracts. Nmap, WhatWeb, Nikto, Nuclei, ffuf, Katana, Subfinder and endpoint mapping remain blocked pending that audit; no project batch runner until full gate acceptance.
2. **PX-003 remaining evidence/provenance coverage (P0):** inventory adapter-specific missing negative/partial golden packs and untested byte/JSONL source traceability. Extend HTML/PDF long-report and source-quote parity only for demonstrated gaps; do not duplicate existing fixtures.
3. **PX-001 field acceptance (P0):** use the published Windows/Kali worksheets on disposable operator-owned environments. Record binary hash, OS, result, evidence and independent reviewer. CI does **not** sign off physical Npcap/UAC or production restore behavior.
4. **PX-004 data-recovery follow-up (P0):** [#163](https://github.com/spk-c/PenX/pull/163) hardened SQLite WAL/journal rejection and [#164](https://github.com/spk-c/PenX/pull/164) hardened backup metadata. Next design an independently verifiable MariaDB-native recovery gate (SQL provenance, pre-restore backup, maintenance isolation, scratch/rollback, owner approval); keep live restore unavailable. Independent Windows/SQLite client/WAL acceptance remains outstanding.
   **Merged follow-ups:** [#168](https://github.com/spk-c/PenX/pull/168) and [#169](https://github.com/spk-c/PenX/pull/169) cover bounded offline SQL red flags and incomplete lexical tails. Continue only with provenance/semantic validation and independent restore safety; lexical warnings never authorize execution.
5. **PX-403/PX-501 next field gates:** [#165](https://github.com/spk-c/PenX/pull/165) added an offline synthetic AI-evidence rubric (not measured model accuracy); separately validate actual local model runs and independent human-labelled data. [#166](https://github.com/spk-c/PenX/pull/166) hardened the opt-in CI/SARIF example; its workflow remains manual-only, with end-to-end proof still needed. **Only then consider PX-102 (P1, large):** durable job journal/restart state after accepted PX-101 grants and PX-004 recovery; never auto-resume consent-gated active adapters.

Each slice requires its own issue/PR, before/after tests, security review and an explicit remaining-gates list. Prioritize blocking P0 regressions over new features; do not combine these tasks into one broad PR.

**Parallel safe source progress (4 November):** [#170](https://github.com/spk-c/PenX/pull/170) adds bounded redacted SQLite history pages (PX-104 partial). [#171](https://github.com/spk-c/PenX/pull/171) adds offline CycloneDX/SPDX inventory counts (PX-304 partial), not advisory scanning. These do not unblock PX-102 recurring/network work or PX-004 database recovery.

## 12. Release-wide metrics (proposed targets, not measured baselines)

| Metric | Desired direction / example threshold | Measurement |
| --- | --- | --- |
| Unsupported security claim rate | 0 emitted as CONFIRMED without source-backed proof | Adversarial source/evidence fixture suite |
| Cross-format evidence parity | 100% on canonical test corpus | JSON/SARIF/HTML/PDF golden assertions |
| Out-of-scope scanner dispatch | 0 in rejection/cancellation test matrix | Scope and planner fuzz/property tests |
| Crash recovery/data loss | 0 committed records lost in controlled kill/restart matrix | SQLite/MariaDB disposable snapshots |
| Report publication reliability | 0 corrupted or half-written final files in fault injection | Atomic publication integration tests |
| CLI startup and per-scan overhead | No regression beyond approved baseline | scripts/refactor_benchmarks.py extensions |
| Human review efficiency | Compare time-to-triage on fixed synthetic dataset | Operator study, never inferred |
| AI evidence alignment | Improve grounded precision; report measured precision AND recall | Curated model benchmark, opt-in real inference |
| Package integrity | All published hashes/asset paths verified | Tagged CI + independent download validation |
| Accessibility | Keyboard/no-color/small-terminal regression coverage | Console snapshots and actual terminal field checks |

## 13. Definition of done for **every** Codex feature

- [ ] Baseline code and overlapping work audited; feature identified as missing/partial rather than assumed absent.
- [ ] Threat model and scope change documented (network, consent, data, subprocesses, secrets).
- [ ] Typed API/domain contract designed, including backward-compatibility and migration strategy.
- [ ] Small, testable implementation with explicit failure behavior; no unbounded loops or token/response growth.
- [ ] Deterministic happy-path, failure, cancellation, malformed, concurrency, privacy and upgrade tests as applicable.
- [ ] Existing offline suite and relevant Linux/Windows/migration/release tests green, with exact commands/results noted.
- [ ] README/feature docs, help output, versioned schemas and changelog updated only where behavior changed.
- [ ] No P0 regression, no unexpected external network access, no extra dependencies without rationale.
- [ ] Feature work pushed to dedicated branch, PR opened/updated, review comments addressed; no bypass of main protection.
- [ ] Experimental/field-only behavior labeled as such; no release or sign-off without approved field evidence.

## 14. Code locations for Codex

| Concern | Start here |
| --- | --- |
| CLI/UX | src/penx_app/cli/, src/penx_app/application/scan_guidance.py |
| Authorization and scope | src/penx_app/scanners/scanner_targets.py, domain/scan_plan.py, application/preflight.py |
| Profiles and planning | application/scan_profiles.py, application/scan_planner.py, application/profile_documents.py |
| Adapter execution | scanners/registry.py, scanners/tools.py, scanners/process_runner.py |
| Evidence and results | domain/evidence.py, domain/scan_models.py, application/scanner_observations.py |
| Findings and trend | domain/finding_identity.py, domain/finding_policy.py, application/scan_trends.py |
| Local AI | analysis/analysis_pipeline.py, analysis/structured_scan_evidence.py, analysis/assessment_quality.py |
| CVE intelligence | intelligence/cve_engine.py, intelligence/cve_priority.py, intelligence/vendor_status.py |
| Persistence | storage/schema_migrations.py, storage/session_repository.py, storage/raw_artifacts.py |
| Reports and schemas | reporting/, docs/schemas/ |
| Packaging | scripts/build_windows.py, scripts/build_linux.py, packaging/linux/, .github/workflows/ |
| Existing acceptance | docs/FIELD_ACCEPTANCE.md, docs/LINUX_ACCEPTANCE_2026-11-02.md, tests/kali_local_scanner_acceptance.py |

## 15. Codex handoff

**Start with [CODEX_EXECUTION.md](CODEX_EXECUTION.md).** It defines the branch/test/review procedure and an initial copy-ready Codex instruction. The small [AGENTS.md](../AGENTS.md) is a map of constraints, not a substitute for the roadmap. Codex must not treat this document as authorization to run real scans, change CI secrets or publish software.
