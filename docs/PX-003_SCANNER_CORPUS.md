# PX-003: scanner corpus inventory and first vertical slice

Baseline: main `f30cfff`, published v0.6.0. No overlapping open PRs;
roadmap issue #123 is planning, not an implemented replacement. PX-003 has
no prerequisite; its fixtures precede PX-002's proposed reason taxonomy.

## Design and acceptance

1. Scope this PR to the existing Nuclei/HTTPx/ffuf JSONL parser boundary.
2. Inventory all 12 scanner choices and the separate endpoint mapper below.
3. Hand-author synthetic inputs; never copy live/domain/provider records.
4. Version inputs and expected stable outcome/export snapshots together.
5. Store input hashes; tests read fixtures without writing or auto-blessing.
6. Exercise actual parsers, typed dispatch, evidence capture and JSON/SARIF.
7. Reject absent/invalid HTTP status and explicit failed HTTPx records.
8. Preserve valid 429 responses as observations, not successful vulnerability checks.
9. Mixed valid/invalid records retain evidence but have PARTIAL coverage.
10. Faults must not disclose discarded scanner error strings or URL secrets.
11. Block network, DNS resolution and child-process creation in the runner.
12. Keep COMPLETE/PARTIAL/FAILED, consent, CLI and schema versions unchanged.
13. No persistence/interface migration or new dependency is needed.
14. Rollback is a normal revert; no database or released artifact changes.
15. Existing standalone unittest discovery integrates the pack with offline_tests.py/CI.
16. Keep full cross-format and all-adapter fixture migration explicitly deferred.

## Existing coverage map

This is a source/test inventory, not measured coverage percentages or field
sign-off. `shared` means a process/dispatch contract, not a dedicated parser
fixture for that adapter. References are existing test modules under `tests/`.

| Adapter / parser | COMPLETE, PARTIAL, FAILED | Timeout / cancellation | Corrupt or contradictory / dependency absence | Versioned corpus in this PR |
|---|---|---|---|---|
| Nmap / XML + text observation | scan_quality, native_cancel_dispatch, scanner_outcome_status | shared process runner; native_cancel_dispatch | scanner_targets_refactor; preflight; malformed XML cases in cve_discovery | deferred |
| WHOIS / python-whois mapping | windows, audit_followup_20261019 | python_scanner_cancel; library timeout not a dedicated corpus | empty registry covered; malformed mapping/dependency fixture deferred | deferred |
| WhatWeb / native text + Python fallback | scanner_outcome_status, scan_quality | scan_quality timeout; native_cancel_dispatch | fallback, missing Ruby/script: preflight, first_run_setup | deferred |
| HTTP headers / requests | scanner_outcome_status | python_scanner_cancel | cookie redaction: native_web_scanners; request failures covered | deferred |
| DNS / dnspython | scanner_outcome_status, windows | python_scanner_cancel | empty records covered; malformed record corpus deferred | deferred |
| Nikto / text | scan_quality, scanner_audit_20261019 | shared runner; native_cancel_dispatch | exit-zero connection errors, TLS/error limit covered; preflight | deferred |
| Nuclei / JSONL | native_parser_audit, native_loss_audit | shared runner; native_cancel_dispatch | malformed, severity, identity clipping, templates/dependencies covered | baseline pack |
| HTTPx / JSONL | native_web_scanners, native_parser_audit | shared runner; native_cancel_dispatch | missing/wrong CLI covered; missing/invalid status and failed rows are a confirmed gap | baseline + adversarial cases |
| ffuf / JSONL | native_web_scanners, native_loss_audit | native time-limit regression; native_cancel_dispatch | wordlist/dependency covered; standalone parser accepts invalid status although endpoint mapping rejects it | baseline + adversarial cases |
| Subfinder / JSONL hosts | native_discovery_jsonl_integrity | shared runner; native_cancel_dispatch | invalid host, mixed JSON, scope and empty output covered | deferred |
| Katana / JSONL requests | native_discovery_jsonl_integrity, discovery_tls | failed request and native_cancel_dispatch | malformed endpoints, scope, dependency covered | deferred |
| TLS / verified socket + certificate | discovery_tls | python_scanner_cancel | protocol/certificate failures covered; malformed certificate corpus deferred | deferred |
| Endpoint mapping / Katana then ffuf | endpoint_inventory_mapping, scanner_audit_20261019 | cancelled stages, shared timeout | strict status codes, same-origin/wordlist/budget/persistence covered | deferred |

Shared coverage: scanner_cancellation, cooperative_scanner_cancel and
scanner_process_tree exercise real synthetic child processes; adapter_provenance
checks source-bound evidence; scanner_result_boundary/telemetry tests exercise
metadata/status compatibility. Existing cases are retained, not bulk duplicated.

## Confirmed gap and expected delta

Before this PR, standalone HTTPx/ffuf summarization treats a URL with no
status, a boolean/non-HTTP status, or an HTTPx failed record as COMPLETE with
evidence. This can falsely establish endpoint coverage. EndpointInventory
already rejects non-integer/out-of-range ffuf status values.

The new adversarial cases must fail before the minimal parser correction.
Only valid integer HTTP status codes 100–599 establish response evidence;
HTTP errors such as 429 remain real responses. A rejected record mixed with
a valid response makes the result PARTIAL, not a fully completed collection.

## Limits / follow-up

This is the first PX-003 slice, not completion of the roadmap item. Pack
coverage for other adapters, byte-decoding/oversize subprocess fixtures,
HTML/PDF parity, and richer raw-JSONL-to-summary provenance remain open.
Current quote checks bind exported findings to the actual adapter summary;
they do not invent byte offsets into the pre-summary JSONL stream.
No real scanner, external target or model is invoked by this pack.

## Executed validation and delta

- Baseline Windows: `python offline_tests.py` — all 227 suites PASS;
  `python scripts/validate_distributions.py` — PASS.
- First checkpoint: five normal/rate-limited snapshots passed using the old
  parser. Seven added adversarial snapshots then failed before the correction.
- Corrected corpus: `python tests/test_scanner_golden_corpus.py -v` — four
  tests PASS, replaying 12 snapshots plus 36 status/failure-field mutations.
  All seven reproduced outcome regressions are corrected.
- Existing native suites: `python -m unittest discover -s tests -p 'test_native*.py'`
  — 68 tests PASS, two Linux-only skips on Windows.
- Final Windows: `python offline_tests.py` — all 228 suites PASS;
  `python scripts/validate_distributions.py` — PASS. UTF-8 mode matches CI.
- Ruff fatal/W/B checks, source unused-import checks, full-source mypy and
  `git diff --check` — PASS after binding the corpus callback's loop value.
- Kali VM replay — NOT RUN: SSH connection timed out. This is not a parser
  failure or field sign-off. Ubuntu regression and existing loopback-only
  Kali package smoke are tracked separately in PR CI results.

No roadmap completion checkbox is changed. The delta is one discoverable
offline suite and stricter response evidence for two existing parsers;
the all-adapter golden corpus remains partial.

## Continuation: ambiguous JSONL records

This checkpoint stays within the same three-parser boundary. Duplicate
fields previously allowed a later value to conceal an earlier failure/status
or change a Nuclei severity. Non-finite JSON constants were also accepted.
Add hand-authored ambiguous records before changing decoding, then reject
the whole offending record without echoing its content. Independent valid
rows must survive as PARTIAL evidence, with unchanged JSON/SARIF schemas and
summary-bound evidence anchors. Include repeated-key checks inside nested
objects, and ensure identical duplicate *records* remain valid observations.
Use the existing discard accounting; no new taxonomy, scanner, dependency,
migration or external I/O. Rollback remains a normal revert. Results below
will distinguish the intentionally failing regressions from final checks.

- Red run: six duplicate-field snapshots plus nine non-finite-constant
  combinations failed before the decoder change (15 failing subcases).
- Targeted replay: six tests PASS over 18 snapshots, the original status
  mutations, non-finite rows alone/mixed with valid rows, finite/string
  controls and repeated-record controls. JSON/SARIF and source-quote checks
  include the newly rejected cases and their valid neighbors.
- Existing native suites, Ruff fatal/W/B checks and full-source mypy PASS.
- Final full offline/distribution checks and current-commit CI are pending.
