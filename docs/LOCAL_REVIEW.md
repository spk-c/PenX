# Optional local-AI draft review

Scanning, profiles and guided collection work without AI. To request an
additional bounded review of a headless collection report, explicitly invoke:

```text
python penx.py review-scan reports/penx_scan.json --model your-loaded-model --endpoint http://127.0.0.1:1234 --output ./reports
python penx.py review-scan reports/penx_scan.json reports/penx_scan_1.json --model your-loaded-model --batch-budget 300
```

This sends selected observation excerpts to a loopback API and writes a separate
`penx_review.json` draft, with a SHA-256 link to the exact source file. Existing
findings, evidence, severity, coverage and CI policy are not modified. The draft
is marked `draft-unverified`; omitted findings stay unreviewed. No target is
contacted by this review path. No scanner, shell command, search, remediation or
follow-up action is executed.

Batch mode accepts at most 10 explicit source files, with one bounded request
per report and a `--batch-budget` of 5–600 seconds (default 600). Admission of
each report checks the remaining budget and reduces its read timeout. This is
cooperative admission/I/O control, not a hard wall-clock interrupt. Independent
reports continue after one failure. A separate `penx_review_batch.json` manifest
records source hashes, draft filenames and sanitized errors. Partial failure
returns exit 1; it never rewrites successful drafts or the source reports.

Only literal loopback addresses and `localhost` are accepted. `localhost` is
converted to `127.0.0.1` without DNS discovery. Environment proxies and HTTP
redirects are disabled. Choose an explicit loaded model: model discovery,
automatic retries and cloud fallback are disabled. A local server can itself be
configured to relay requests; operate it with locally hosted weights if local
processing is required. Authentication uses `PENX_LLM_API_KEY` from the process
environment, never from an exported profile or command-line argument.

The server must support schema-constrained chat completion. Unsupported servers,
truncated answers, reasoning-only output, tool calls, malformed JSON, unknown
fields and duplicate keys fail without publishing a draft. No model call was
made during development verification; transport tests use synthetic sessions.

## Bounds and evidence rules

- Source `penx-scan-v1` file: at most 4 MiB and 1000 findings. Duplicate
  fingerprints are rejected as ambiguous rather than merged automatically.
- One request, at most 20 findings (`--max-findings 1..20`), a 24,000-character
  prompt and 2048 output tokens. Server response: at most 64 KiB.
- Connect timeout: 5 seconds. Read timeout: `--timeout 5..120` seconds (default
  60). This is an I/O inactivity timeout, not a hard whole-request deadline.
- Every returned finding must reference a supplied fingerprint. Evidence quotes
  must be exact substrings of the supplied excerpt, at least 12 non-padding
  characters and at most 1000 characters. This validates citation consistency,
  not source authenticity or vulnerability applicability.
- Without a quote, an item must remain `insufficient_evidence`. Other allowed
  draft assessments are `needs_review` and `informational`; confirmed/resolved
  states are not available.
- Optional scanner suggestions may reference only the original recorded scanner
  selection. They are manual suggestions with no execution or authorization
  attached. Target changes, commands and transferable consent have no schema
  fields and are rejected.

Exit 0 means a validated draft was published, 1 means review unavailable or
rejected, and 2 means command-line usage error. Even a validated draft requires
human review. Report provenance and hashes remain separate from AI judgment.
