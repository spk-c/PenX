# PenX targeted code audit — 17 October 2026

## Scope and methodology

**Baseline:** `ead89d87a24089fc4c899425004efe3368ec96e8` on `main`, before this fix.

This was a **targeted source audit**, not a claim that every line in PenX
has been manually reviewed. Repository inventory, current source, existing
regression tests and acceptance worksheets were reviewed. The review focused
on boundaries most likely to produce incorrect security findings, data loss,
or misleading success states:

1. **Session and evaluation persistence:** `storage/db.py`,
   `storage/db_backend.py`, `storage/db_evals.py`,
   `application/assessment_service.py`, and corresponding atomic/SQLite tests.
2. **Scanner input and evidence:** `scanners/scanner_targets.py`,
   `domain/scan_models.py`, and scanner regression contracts.
3. **LLM handling:** `analysis/llm_client.py`,
   `analysis/scan_input_budget.py`, and model transport tests.
4. **Research and update trust boundaries:** `intelligence/search.py`,
   `intelligence/nvd_disk_cache.py`,
   `intelligence/package_inventory.py`, `updates.py`, and offline tests.
5. **Reports and recovery:** `reporting/report_batch.py`,
   `reporting/report_management.py`, `file_output.py`,
   `application/scan_recovery.py`, and report-staging tests.
6. **Release and CI acceptance:** `docs/REFACTOR_ACCEPTANCE.md`,
   `docs/FIELD_ACCEPTANCE.md`, and repository Actions/check definitions.

No live scan, production database, private user files, Windows hardware
acceptance, or external network fuzzing was performed in this review.

## Confirmed finding: RCV-01 — recovery snapshots can be partially published

**Severity:** Medium (local data integrity and recovery reliability).

**Source:** `src/penx_app/application/scan_recovery.py` prior to this PR.

Both `save_unanalysed_recon()` and `save_unsaved_assessment()`
opened the *final* recovery path with `O_CREAT | O_EXCL`, then wrote directly
to it. Exclusive creation protects earlier snapshots from overwrites, but
does **not** make an individual snapshot complete or atomic. A failed write,
JSON serialization error, or interrupted process can leave an incomplete
`recon_SL*_unanalysed*.txt` or `assessment_SL*_unsaved*.json` that
looks like a valid recovery artifact. Subsequent retries use new suffixes,
leaving the incomplete file in place. This can mislead manual recovery.

**Fix in this PR:** use the existing reviewed `publish_unique()`
helper in `file_output.py`, which stages content in the same directory,
flushes and `fsync`s it, atomically creates an exclusive final hard link,
and removes the temporary path. Serialize JSON before publication; validate
session IDs as positive integers and payload types before creating any files.
Keep filenames, retry suffixes, and notifications compatible.

**Offline regressions:** validate two no-overwrite snapshots, complete
Unicode JSON, cyclic JSON serialization failures, UTF-8 encoding failures,
simulated publication failures, invalid session IDs, invalid payload types,
and no stray staged files.

## Remediation follow-up — 17 October 2026

The following additional hardening changes have **passed all required
CI checks and been squash-merged into main** after this original audit:

| Audit item | Remedy | Merged PR / commit |
| --- | --- | --- |
| NVD cache: size check followed by a fresh path read | Open one non-symlink, regular file descriptor; validate open-file identity and bound actual bytes read. Non-serializable best-effort writes now fail without crashing CVE discovery. | [#57](https://github.com/spk-c/PenX/pull/57) / `17887fd821702e5785354a63bab77e2507dfaa59` |
| Package inventory: `stat()` then `json.load()` | Open once, reject swapped or symbolic-link paths and enforce the byte limit on the opened descriptor. | [#57](https://github.com/spk-c/PenX/pull/57) |
| Arbitrary public-name DNS rebinding during HTTPS research | Verify public A/AAAA endpoints as sockets are created, connect directly to checked address without another DNS lookup, preserve TLS hostname validation, and ignore untrusted proxy environment configuration. | [#58](https://github.com/spk-c/PenX/pull/58) / `a69a986010373614249b5ed252652194be0d2f25` |

Seven offline tests cover local file boundaries, and eight test public HTTPS
DNS/socket behavior without making real connections. Ubuntu and Windows offline
tests, the Windows package/installer smoke test, Python compatibility contracts,
dependency scanning, CodeQL and Gitleaks passed for each PR. This certifies
those test cases **only**.

### Remaining acceptance items — not automatically fixable in CI

The original Windows/Npcap/UAC field trials, all 12 scanner modes on
authorized disposable targets, physical installer upgrade/rollback,
sanitized SQLite/MariaDB backup restoration, power-loss report recovery,
real rendered PDF review and model-runtime compatibility evidence still
require independent operator execution and recorded sign-off per
[`REFACTOR_ACCEPTANCE.md`](REFACTOR_ACCEPTANCE.md). These are *unperformed
validation activities*, not necessarily reproducible code bugs. The
refactor remains **NOT SIGNED OFF** until the worksheet gates are satisfied.

## Other audit observations and limitations

| Area | Verified observation | Status / follow-up |
| --- | --- | --- |
| Database changes | Session ownership checks and transaction rollbacks exist; SQLite placeholder adaptation avoids quoted/comment content | Existing automated coverage, not a production restore certification |
| Scanner execution | Argument validation, typed status/evidence contracts and cancellation handling are present | Real process-tree/UAC/Npcap and all 12 authorized scanner modes still require field evidence |
| LLM model output | Responses use content extraction and incomplete-result safeguards; reasoning output is not treated as final report | Behavior across actual configured local model and multiple server versions still needs field tests |
| Public research | HTTPS source and request restrictions exist, with bounded search/page outputs | Public DNS rebinding is acknowledged in the code as outside the page filter's guarantee |
| Report publication | Per-session locks, staged validation, backup/rollback, manifests and symlink checks are present | Real power-loss and cross-process Windows filesystem behavior needs field evidence |
| Local NVD cache | TTL/key/type/size checks and atomic cache writes are present | Size pre-check followed by a separate file read is not a race-proof bound; harden on a separate tracked change if threat model includes hostile local writers |
| Inventory import | Input limits and exact package-version checks exist | Separate `stat()` and `json.load()` also depend on a stable local file; no hostile-local-writer test was run |
| Release updater | Official release URLs, exact SHA-256 asset verification, maximum installer size and explicit opt-in are enforced in code | Genuine Windows installer upgrade/rollback and signing are not proven by this audit |

The source-level file-read and DNS hardening items described above were
implemented after this initial audit; the original observations remain here
for traceability. They are not assigned CVE identifiers or treated as proof of
external exploitability.

## Validation and merge policy

- Run all repository offline regression tests on both Ubuntu and Windows.
- Run the configured Python 3.10/3.11/3.12 compatibility checks, package tests,
  CodeQL/secret/dependency scanning, and Windows packaged-app smoke checks.
- Review results against **this PR's head SHA**, not an earlier green commit.
- Merge only if the required jobs are successful.
- This patch changes source code on `main` only after merge. A previously
  published release binary does not automatically gain this fix.

## Overall audit verdict

**One confirmed recovery data-integrity defect fixed in this PR.**
The examined persistence/report/scanner/model boundaries have substantial
existing tests; that coverage does **not** mean PenX is bug-free. The canonical
`docs/REFACTOR_ACCEPTANCE.md` correctly remains **NOT SIGNED OFF** until its
specified physical Windows, authorized scanner, sanitized database restore,
installer rollback, recovery and rendered-report evidence is reviewed.
