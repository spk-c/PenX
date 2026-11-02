# PX-003: process byte corpus (dependent on PR #125)

Base: `0f3fe4d`. Merge #124 then #125; synchronize updated main into this
follow-up before retargeting it. Do not merge or publish from this task.

## Design and acceptance

1. Existing timeout/tree cleanup, pre-cancellation, early EOF and ASCII
   truncation tests already cover those contracts; retain them unchanged.
2. Add versioned synthetic byte fixtures, not live scanner captures.
3. A fixed Python child writes fixture files; payloads never become code/flags.
4. Require identical live/quiet outcome and JSON/SARIF coverage semantics.
5. Stderr-only output must not establish successful stdout evidence.
6. Preserve separate bounded streams and the existing `[STDERR]` section.
7. Decode captured bytes strictly before trusting evidence; replacement display
   remains available but corrupt UTF-8 becomes PARTIAL with evidence=false.
8. Valid Unicode, a literal replacement character and split UTF-8 remain valid.
9. Test exact/overflow byte limits, including multibyte and malformed input.
10. Reuse the quiet runner's process lifecycle for live capture/rendering.
11. Keep the existing raw-byte cap per stream, bounded read chunks and draining.
12. Preserve timeout/cancellation/nonzero-exit precedence and descendant cleanup.
13. Missing executables and injected permission denial fail without evidence.
14. No network, scanner executable, target expansion, dependency or migration.
15. No schema or reason-taxonomy change; rollback is an ordinary revert.

## Limits

This is process-boundary coverage, not a complete scanner corpus or field
sign-off. Successful mixed-stream text still includes labeled diagnostics for
legacy readers; attributing every parsed line to a raw byte stream remains
future work. Other adapter packs, HTML/PDF parity and raw-byte evidence anchors
remain open. Permission denial is injected, not an OS ACL field acceptance.
