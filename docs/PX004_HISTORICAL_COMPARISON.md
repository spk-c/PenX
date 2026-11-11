# PX-004: bounded historical-to-scratch fingerprint comparison

This is an **opt-in offline comparison primitive**, not a SQL importer, trusted
attestation service, backup creator, signing mechanism or restore feature. It
addresses one part of [#188](https://github.com/spk-c/PenX/issues/188).
Independent operator field acceptance remains **NOT SIGNED OFF**.

## Four separate evidence stages

1. **Historical source snapshot** — an independent, operator-controlled
   READ ONLY transaction at a recorded UTC instant, with the schema and
   canonical row multiset fingerprints. Record the evidence file digest in a
   separately controlled ledger (ideally with an independently verified
   signature and trusted timestamp). This repository has no signing/PKI
   implementation and cannot authenticate the origin of a supplied digest.
2. **Saved dump bytes** — independently verify the existing SQL + JSON
   manifest and both previously stored SHA-256 pins using
   `backup mariadb-verify-pinned`. This proves byte identity to the pins,
   **not** a historical snapshot or safe SQL syntax. The metadata records
   the intended dump digest; matching a text field is not rehashing SQL.
3. **Isolated scratch import** — performed **outside this module** by a
   separately authorized human in a disposable database; never production
   or the original source schema. A partial failed import must be discarded,
   not resumed under a "verified restore" label. Capture a fresh READ ONLY
   scratch snapshot with a separately restricted user.
4. **Offline comparison** — `compare_historical_evidence()` checks a
   independently pinned historical JSON record against a scratch JSON record.
   It never connects to any database, reads SQL or invokes subprocesses.

Do not infer that the historical reference and dump were captured from a
*single consistent source transaction* just because they share a date/digest.
A current source snapshot and a historical dump are different evidence.

## Record format (both stages)

Only synthetic metadata belongs in tests and the repository. Each record is a
UTF-8 JSON object with **exactly** these fields:

```json
{
  "schema": "penx-mariadb-content-evidence-v1",
  "role": "source",
  "database": "penx_ci_test",
  "observed_at": "2026-11-01T12:00:00Z",
  "dump_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "structure_sha256": "1111111111111111111111111111111111111111111111111111111111111111",
  "tables": [
    {
      "name": "history",
      "rows": 2,
      "content_sha256": "2222222222222222222222222222222222222222222222222222222222222222"
    }
  ]
}
```

The scratch record has `role: scratch`, a distinct disposable database
name, a later observation timestamp, and its own measured fingerprints.
Never copy fingerprints from the historical reference into the scratch record.
The caller must independently bind `expected_source_record_sha256` to the
source JSON's bytes *from a previously trusted location*, and supply the
already independently verified original dump digest. Self-generated hashes
supplied alongside self-generated evidence **do not authenticate provenance**.

`structure_sha256` means the SHA-256 of the canonical structural metadata
constructed in `mariadb_restore_audit.audit_scratch_restore`; table
`content_sha256` means the existing
`mariadb_restore_audit._content_fingerprint` canonical, order-independent
row multiset SHA-256. The latter preserves duplicate multiplicity and
encodes value types, not merely `COUNT(*)`. Both stages must use the same
capture algorithm and input schema; **do not** hand-calculate hashes from SQL
text or compare values encoded by a different application.

The primitive accepts at most 64 KiB per evidence record, 100 tables,
2,000 rows per table, and 10,000 rows total, and rejects duplicate keys,
duplicate tables, malformed UTC dates/digests, symlinks, mismatched stages,
schema drift, missing fields, changed values despite identical row counts,
and mismatch to the externally retained source-record digest.

For programmatic use in a controlled, offline acceptance harness:

```python
from penx_app.application.mariadb_historical_compare import compare_historical_evidence

result = compare_historical_evidence(
    source_path="historical-reference.json",
    scratch_path="disposable-scratch.json",
    expected_source_record_sha256="64-lowercase-hex-from-independent-ledger",
    expected_dump_sha256="64-lowercase-hex-from-verified-original-dump",
    source_database="penx_ci_test",
    scratch_database="penx_restore_fixture",
)
```

The placeholders are intentionally invalid until replaced with verified
values. A successful result is named
`offline-record-fingerprint-match-only` and **always** includes
`historical_source_authenticated: false`,
`historical_backup_rows_verified: false`,
`sql_semantics_verified: false`, `restore_available: false`,
`sql_executed: false` and `database_modified: false`.
It does not guarantee that evidence was captured at the claimed time,
that an SQL dump would import, or that a malicious/incorrect original
snapshot was truthful. Time ordering is a consistency gate, not a trusted
timestamp.

## Acceptance and rollback boundaries

The synthetic regression suite is
`python -m unittest discover -s tests -p test_px004_historical_evidence.py -v`
with `PYTHONPATH=src`. It covers matching fingerprints, same-row-count changed
values, schema/count drift, external pin tampering, truncated/duplicate JSON,
overlong files, row budget, stage/binding mismatches, invalid dates and symlinks.
The existing disposable MariaDB CI tests cover aborted scratch import, not
independent production recovery. WAL/journal races require separate SQLite
operator verification; missing privileges and interrupted real restore need
operator-controlled VM/database evidence.

No migration, persistent state or backup files are modified; rollback of this
slice is simply reverting the pure helper and test. This change does **not**
close #188 or enable live/in-place MariaDB restoration. A genuine field PASS
needs independent source capture provenance, isolated import evidence,
least-privilege/snapshot/rollback validation and reviewer sign-off in
[FIELD_ACCEPTANCE.md](FIELD_ACCEPTANCE.md).
