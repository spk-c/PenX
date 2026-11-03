# PX-003 — Retained capture provenance verification

PenX can already retain optional scanner-output captures with bounded SHA-256
references. This change makes a **full-capture integrity** check mandatory
whenever a persisted evidence quote is revalidated against a retained capture.

## Offline operator workflow

Capture retention is explicitly opt-in, not enabled for ordinary scans:

```text
python penx.py scan --target example.test --authorized --scanners 4 --raw-artifacts ./raw
```

The target above is illustrative only; use targets you own or are authorized
to assess. To inspect the original saved **ScanResult.metadata()** JSON in an
offline session, place its exact contents in `metadata.json` and run:

```text
python penx.py evidence verify --metadata metadata.json --artifacts ./raw
```

The command reads only the supplied local metadata document and local
artifact files. It never contacts a scanner or a network target, launches
external commands, uploads source text, or modifies saved assessments.

Successful output is a single JSON summary indicating
`verified-retained-integrity`, number of complete source captures and
number of persisted quote anchors rechecked. Neither raw text nor API keys
are printed. Metadata inputs are limited to 100 KiB. Stored source sizes
are individually capped at 1 MiB and names are SHA-256 based.

Missing, tampered, oversized, relocated, linked or no-longer-available
captures fail closed; an old v1/v2 assessment without retained captures
cannot be retrospectively certified. When retained SHA metadata is
present, passing the same source quote inside a **different** scanner text
is no longer enough: the UTF-8 length and full-source SHA-256 must match
before accepting any quote offsets.

## Trust boundaries and remaining work

This proves the integrity of **UTF-8 scanner text as captured by PenX**,
not the original operating-system stdout byte stream or network packets.
Capture hashes are not digital signatures and do not attest scanner
identity, authentic execution, CVE applicability, human review or the
accuracy of an associated AI assessment. Existing report fields saying
`stored-reference-not-revalidated` remain unchanged until a user
explicitly performs the offline check.

No database migration, changes to existing JSON/SARIF exports, automatic
retention, scanning behavior, field acceptance or published release.
Remaining PX-003 work includes other third-party adapter negatives,
original pre-decoding stdout byte provenance and independent visual PDF
and OS field reviews. Rollback is a revert of the focused PR.
