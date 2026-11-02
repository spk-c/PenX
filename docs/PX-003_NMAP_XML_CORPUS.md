# PX-003 — validated Nmap XML port corpus

**Baseline:** `main` after [#128](https://github.com/spk-c/PenX/pull/128); part of [roadmap #123](https://github.com/spk-c/PenX/issues/123). The 15 XML fixtures in `tests/fixtures/scanner_corpus/nmap_xml_ports_v1.json` are hand-authored and never obtained from an external scan.

## Confirmed issue

`analysis/structured_scan_evidence.py:nmap_records` validated Nmap TCP/UDP ports and the range 1–65535, but `int(number)` could raise on a huge untrusted numeric port ID. `intelligence/cve_observations.py:parse_nmap_services` did **not** validate Nmap protocol/port IDs at all before adding a CPE product to the advisory research inventory.

A broken XML record could therefore be silently excluded by the structured inventory while its bogus `portid=65536` or `protocol=icmp` remained an apparently valid CVE research candidate.

## Implementation

- Add a single pure `validated_nmap_port(protocol, number)` helper shared by both parsers; restrict to TCP/UDP, ASCII decimal of 1–5 characters, and port 1–65535.
- Return canonical decimal port IDs (e.g. `00022` becomes `22`) so both outputs use the same identity. Reject overlong numeric strings **before** calling `int`.
- Preserve explicitly valid neighboring service observations when an invalid XML sibling is omitted. Retain existing CPE-version contradiction rules.
- Keep product evidence a **candidate for research**, not proof of a vulnerability. XML alone creates no verified finding in headless JSON/SARIF.
- Do not change CLI, schema, scan parameters, target scope, consent policy, raw artifacts or database migrations.

## Offline test matrix

15 fixtures cover TCP/UDP, lower/upper boundary, zero, negative, invalid sign/content/non-ASCII digits, impossible protocols, closed state, contradictory service/CPE versions, multiple port siblings, canonical leading zeros and excessively long decimal input.

`tests/test_nmap_xml_port_corpus.py` exercises both real parsers, checks full per-case product/structured inventory expectations, and validates that no scanner inventory alone produces an automatic vulnerability in JSON/SARIF. External socket/DNS/request/subprocess activity is prohibited by tripwires.

## Remaining work

PX-003 is **not complete**. Still missing: additional adapter-specific golden packs, HTML/PDF presentation parity from comparable stored assessments and original byte/JSONL source provenance. No real host scanning, live CVE lookups, field sign-off or release is included here. Rollback requires only reverting this PR.
