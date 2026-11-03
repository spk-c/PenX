# PX-002 historical metadata shape validation

The existing `ScanResult.from_metadata` parser already rejects malformed
types, failed outcomes claiming evidence, unknown reason codes, duplicate JSON
fields and invalid evidence/run-event blocks. This focused P0 slice closes
another demonstrated gap: a v1 or v2 JSON record could carry an unsupported
v3 `plan` or an arbitrary per-adapter `is_clean` claim. The parser silently
discarded these fields and continued with an apparently complete assessment.

This slice applies exact per-version allowlists to top-level and per-adapter
fields. Valid v1, v2 and v3 metadata retain the same decoding and original
version-specific serialization. New unsupported claim fields fail explicitly
instead of being normalized away. No stored rows, migrations, CLI flags,
network adapters or report schemas are modified.

Offline test matrix: historical positive v1/v2/v3; newer plan smuggled into
v1/v2; unknown top-level claim v1/v2/v3; unknown per-adapter claim v1/v2/v3;
valid v2 records and v3 machine-readable reason. The negative cases failed
before the patch, passed afterward. Existing legacy record tests still pass.

Remaining acceptance: real historical customer databases (with backups),
all adapter-specific error/timeout/invalid-output cases, live TUI parity and
independent review remain outside this change. Rollback: revert the focused
PR; no schema migration and no data rewriting.
