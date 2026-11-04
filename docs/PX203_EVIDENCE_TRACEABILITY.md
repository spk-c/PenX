# PX-203 — Saved-report evidence traceability (first slice)

**Status:** additive partial implementation; **not a vulnerability probability,
automatic exploitability score, independent source verification or full PX-203
operator acceptance**.

PenX now returns a separate `evidence_quality` object for saved findings in
the existing `penx-assessment-v1` JSON export, and an equivalent
`evidenceQuality` SARIF result property. HTML/PDF display the same
**traceability tier** next to each finding. There is no new scanner,
configuration toggle, database column, migration, remote request or external
LLM inference.

## Interpreting a tier

| Tier | Meaning | Does **not** establish |
| --- | --- | --- |
| **0/2** | No exact quote match in the saved scan | Absence of vulnerability or coverage |
| **1/2** | An exact quote exists in saved scan text but no unambiguous typed completed source is proven | Independent provenance, applicability, complete coverage |
| **2/2** | That quote also maps to one unambiguous saved scanner section **and** its stored typed metadata reports `COMPLETE` | That the saved raw capture has been independently revalidated, a CVE applies, or an exploit succeeds |

The distinction is an **ordinal local traceability tier**, never a
probability, CVSS/EPSS risk value, claim of human review or proof of
vulnerability. A forged saved scan could still contain matching fabricated
text, and typed `COMPLETE` only reflects stored metadata.

Each vector records quote match, source section identity, typed scanner
coverage, whether a scan date is **recorded** (not a trusted freshness age),
corroboration (always `not-established`), and whether a raw artifact
**reference** was retained (never silently marked revalidated). All entries
explicitly return:
- `original_source_revalidated: false`
- `independent_corroboration_verified: false`
- `vulnerability_verified: false`
- `exploitability_verified: false`
- `operator_review_required: true`

For source-byte verification, use PenX's separate opt-in `evidence verify`
workflow with independently retained original adapter outputs. That workflow
does **not** silently elevate persisted report evidence tiers. Human review
and scope/field acceptance are separate.

## Compatibility, tests, and rollback

Existing finding IDs, rule IDs, confidence labels, fingerprints,
`penx-assessment-v1` and SARIF 2.1.0 envelopes remain unchanged. The new
fields are additive and contain **no raw quote, target hostname, IP, CVE or
scanner text**. HTML uses escaped values; PDF includes only a small bounded
label. Legacy sessions without typed scanner metadata remain tier 1 at most,
and missing quotes remain tier 0 even if a model called them confirmed.

Tests use synthetic complete, partial and missing typed scanner metadata,
ambiguous repeated scanner sections, missing quotes, retained-only artifact
references, cross-format JSON/SARIF vector parity, HTML/PDF tier presence,
headless SARIF compatibility and no scanner/network calls. These do not
replace Windows/Kali/Npcap field tests or actual independent evidence review.

Full PX-203 still requires independent original-source freshness verification,
support for corroborating truly independent sources, better parser
confidence and human report acceptance. Revert the additive module,
machine export properties, view labels and tests to roll back.
