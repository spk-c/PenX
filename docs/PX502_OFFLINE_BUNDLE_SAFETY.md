# PX-502 — Offline bundle safety design

**Status:** Design note + negative fixture coverage for the existing bounded
import. The full interoperable bundle import/export is **deferred** (see
`docs/ROADMAP.md`, PX-502, "Not accepted"). No new uncontrolled import path is
added by this task.

## Goal

Interoperable offline import/export of approved assessment findings, evidence
anchors, machine reports and corrections, with an integrity manifest and
redaction. The import must be bounded, versioned, fail closed on invalid
input, and must never import targets or credentials or overwrite stored user
records automatically.

## Current state

The only existing bounded import path is
`penx_app.application.profile_documents` (scan-profile import/export,
`penx profiles --validate/--export/--copy`). It is already:

- **versioned and field-strict** — `schema_version == 1` is required and the
  field set is closed; unknown fields (including `targets`, `consent` and
  `secrets`) are rejected,
- **size-bounded** — `load_profile` reads at most `MAX_PROFILE_BYTES` (64 KiB)
  and rejects anything larger before JSON parsing,
- **duplicate-rejecting** — `json.loads(..., object_pairs_hook=_unique_object)`
  raises on duplicate JSON fields,
- **not a user-record import** — it reads/writes a standalone profile file and
  never writes to the SQLite/MariaDB store or overwrites existing records.

No assessment-bundle import path exists yet.

## Safety properties (locked in `tests/test_px502_bundle_safety.py`)

| Property | Enforced by | Test |
| --- | --- | --- |
| Integrity (schema version, closed field set, types, numeric bounds, scanner/dependency limits, passive-vs-active invariant) | `ProfileDocument.from_dict` + `__post_init__` | `test_rejects_*`, `test_passive_profile_forbids_active_configuration` |
| Duplicate entries | `_unique_object` (`object_pairs_hook`) | `test_rejects_duplicate_json_fields` |
| Oversized inputs | `MAX_PROFILE_BYTES` (64 KiB) read cap, checked before parsing | `test_rejects_oversized_profile` |
| Privacy (no targets/credentials) | unknown-field rejection | `test_rejects_unknown_fields`, `test_loaded_profile_excludes_targets_and_credentials` |
| Unsafe paths (fail closed) | `Path(...).open('rb')` rejects missing files and directories | `test_rejects_missing_and_directory_paths` |

## Deferred scope

- **Full assessment-bundle import/export** (findings, evidence anchors, machine
  reports, corrections, integrity manifest, redaction) — not implemented;
  remains "Not accepted" in `docs/ROADMAP.md`.
- **Path hardening for import** (reject symlinks / path traversal / absolute
  paths at the import layer). The current loader fails closed on missing files
  and directories, but does not yet resolve/validate the requested path against
  a safe base.
- **Automatic import/overwrite of stored user records** — must remain opt-in and
  would require maintainer review for any schema/migration change.

## Rollback

Test-only change (plus this design note). Removing
`tests/test_px502_bundle_safety.py` and `docs/PX502_OFFLINE_BUNDLE_SAFETY.md`
fully reverts the task. No source code is modified.
