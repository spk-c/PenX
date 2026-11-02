# PX-003: loss-aware discovery limits (depends on PR #126)

Base: `6ccedcf`; merge #124, #125 and #126 first. Synchronize updated main
into this branch before retargeting. No merge or release is part of this task.

## Design and acceptance

1. Existing malformed/cancellation/scope cases are retained, not duplicated.
2. Add bounded, hashed synthetic recipes for exact limits and overflow.
3. Exercise real Subfinder/Katana parsers with process output injected only.
4. More than 100 unique in-scope entries means visibly capped PARTIAL evidence.
5. Exactly 100 entries and repeated duplicate records remain COMPLETE.
6. Keep canonical sorted previews; do not admit the first 100 input rows only.
7. A normalized Katana URL over 350 characters is omitted, never shortened.
8. Retain independently valid short URLs as PARTIAL when siblings are omitted.
9. Long query secrets removed by normalization do not imply identity clipping.
10. Count inventory input rows beyond 3,000 as rejected/unprocessed.
11. Never parse/probe omitted tail rows; existing consent and budgets stay intact.
12. Test actual mapping dispatch with no process, network or persisted writes.
13. Check JSON/SARIF outcomes and exact retained source identities/anchors.
14. Keep API/schema versions, persistence formats and existing numeric limits.
15. No migration/dependency; rollback is an ordinary revert.

Other adapter families, HTML/PDF parity and raw-byte evidence anchors remain
open. These synthetic checks are not independent field sign-off.

## Executed evidence

- Six failing cases reproduced before correction: two preview overflows,
  two overlong-identity cases and two unread mapping-tail cases. All six
  complementary exact-boundary/duplicate/redaction controls already passed.
- `python tests/test_discovery_limits_corpus.py -v` — PASS on Windows and
  Kali; twelve bounded recipes verify status, retained identities, diagnostic
  propagation, JSON/SARIF parity and summary-bound quote matching.
- Existing golden replay (six tests), mapping (18) and native suites (68,
  two Linux-only skips on Windows) PASS unchanged.
- `python offline_tests.py` — all 230 suites PASS on Windows and Kali.
  `python scripts/validate_distributions.py` — PASS on both platforms.
- Ruff fatal/W/B and unused-import checks, full-source mypy and diff
  whitespace — PASS. Final-commit CI is tracked in
  [PR #127](https://github.com/spk-c/PenX/pull/127).
- Windows installer smoke remains NOT RUN for this feature branch. No
  external target, provider query, release or independent field sign-off.
