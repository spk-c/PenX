# PX-003 — saved-assessment HTML/PDF evidence and status parity

Baseline: `main` commit `3453e2bb6fe492b60ab5c74da2f3f82f0c362060`, following the ordered merges #124–#129. Roadmap tracker: [#123](https://github.com/spk-c/PenX/issues/123).

## Confirmed misleading text

The typed `ScanResult` contract permits a scanner to end `COMPLETE` with `evidence=False`: for example, a successful DNS query that returned no usable records. Both HTML and PDF correctly label this **COLLECTED** based on completion rather than finding count. The historical PDF legend, however, said **“COLLECTED means scanner evidence exists”**, overstating the evidence and potentially leading an operator to infer that absence of findings establishes safety. The HTML introduction also referred to collected evidence without distinguishing completion from usable observations.

## Fix and test contract

- Define `COVERAGE_EXPLANATION` in `reporting/scan_coverage.py` and render exactly the same text in HTML and PDF.
- State explicitly: **COLLECTED = selected adapter completed**, not proof it produced evidence or that nothing is vulnerable; **INCOMPLETE = selected adapter did not finish**. Unselected scanners are out of coverage.
- Retain existing badge words and coverage structure to preserve saved-report and CLI compatibility.
- New offline regression `tests/test_px003_saved_report_parity.py` checks a synthetic saved assessment including a completed/no-evidence DNS adapter, incomplete Nikto, completed Nmap, a quote-matched finding, a missing-quote candidate, a rejected finding, a recommendation and a filtered mitigation.
- Exercise the *real* HTML exporter, real report/SARIF projections, the PDF layout flowables and one complete real PDF build. Assert the same active findings, evidence reference, confidence downgrade, scanner completion labels and rejection behavior. No OCR, real network, scanner invocation, model calls or database updates.

## Limits

This is **only** one PX-003 slice: saved-assessment presentation parity. It does not equate the separate headless `penx-scan-v1` format with saved `penx-assessment-v1`, add raw JSONL byte offsets, certify field accuracy or touch any release. Some other adapters still lack dedicated synthetic golden packs. Human field validation remains open.

No new dependencies, schema migrations, target expansion or consent changes. Rollback is a simple revert.
