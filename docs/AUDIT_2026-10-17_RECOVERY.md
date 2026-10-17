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

Potential race-hardening observations are **not** asserted as independently
reproduced vulnerabilities in this audit, and no misleading CVE labels have
been assigned.

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
