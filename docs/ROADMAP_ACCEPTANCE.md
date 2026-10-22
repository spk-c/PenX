# Roadmap acceptance and remaining evidence

This matrix uses the requirements actually tracked in `ROADMAP.md` and the
historical architecture plan. The original external 2026-10-21 brief is absent
here; root `roadmap.md` is excluded by `.gitignore` and is not in the available
Git history. No invented replacement is treated as the original.

`TESTED` means implemented with automated offline evidence, not full field
acceptance. The earlier blanket `COMPLETE` labels overstated this distinction.

| Requirement | Implementation and automated evidence | Remaining acceptance |
| --- | --- | --- |
| Scanner dependency DAG | Explicit profile edges, stable topological scheduling, cycle/scope validation, descendant-only failure skipping; `test_roadmap_gap_closure.py` | Real multi-scanner workload review |
| Sequential/parallel execution, consent, cancellation | Existing executor/process-tree suites plus node deadline and DAG tests | Windows/Npcap/installed scanner field matrix |
| Passive budget/cancellation | Typed headless DNS/CT/RDAP/InternetDB providers, per-provider/global checkpoints, bounded streaming, sequential dispatch intervals; new gap-closure tests | Real provider behavior and authorized operational review; in-flight I/O remains cooperative |
| Evidence, hashes and scan comparisons | Persisted anchors, optional artifact hashes, configuration/dependency snapshots, existing evidence/diff suites | Operator verification of retained captures and long reports |
| Headless finding/severity policy | Nuclei plus selected HTTP/TLS observations; Nmap/Nikto inventory findings stay informational; gap-closure/schema tests | Actual scanner fixture expansion; remaining adapters expose coverage only |
| Typed scanner profiles | Strict allowlists, bounded import/export, graph configuration and unchanged consent; configuration/profile suites | Scanner-specific field checks; no claim of arbitrary/full CLI flag coverage |
| Guided beginner flow | Permission, consent, preflight, final confirmation and explanation tests | Human usability review |
| Local AI automation | Explicit bounded multi-report draft review, literal citations, restricted suggestions and batch manifest; local review and batch tests | Real local model compatibility. Broader agent automation has no recovered acceptance specification and is not claimed complete |
| CI/SARIF | Schemas and optional manual workflow contract tests | Actual authorized workflow execution and SARIF upload |
| Release/install/database recovery | Existing automated regression contracts | `FIELD_ACCEPTANCE.md` remains NOT SIGNED OFF; packaging/upgrade/rollback and independent database recovery evidence are still required |

No live external target, provider, model or CI scan may be claimed tested from
mock results. Completing the remaining field rows requires an explicitly
authorized disposable target/VM, the exact installer/build and operator review.
The missing original brief is also required for a full original-scope audit.
