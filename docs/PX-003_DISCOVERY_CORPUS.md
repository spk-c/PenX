# PX-003 discovery corpus: dependent follow-up to PR #124

Base: `7acad17` on `feature/px-003-scanner-corpus`. Merge #124 first,
then retarget this follow-up to main; no merge or release is authorized by
this work. Keep its diff independent of the preceding native-parser pack.

## Plan and acceptance

1. Stay within PX-003 and reuse the existing read-only golden replay runner.
2. Add synthetic Subfinder/Katana success, mixed and ambiguous JSONL snapshots.
3. Reproduce duplicate-host and duplicate-error cases before modifying decoding.
4. Reject non-finite constants, including in nested objects, consistently.
5. Share the strict decoder already introduced by #124 across scanner inputs.
6. Apply the same policy to Katana/ffuf endpoint-inventory ingestion.
7. Leave persisted inventory-file decoding and its compatibility unchanged.
8. Ambiguous Katana records cannot authorize later ffuf probes.
9. Valid sibling records retain PARTIAL evidence; duplicate records remain valid.
10. Cover failed/partial discovery processes with synthetic credential-like URLs.
11. Omit raw process failure text, as the three native summary adapters already do.
12. Keep status, cancellation, consent, schema and target boundaries unchanged.
13. Exercise JSON/SARIF parity and summary-bound source anchors for five adapters.
14. Block network, DNS and child creation; only scanner process output is injected.
15. No new dependencies, persistence migration, or production state changes.
16. Rollback is a normal revert; all remaining PX-003 families stay open.

## Scope limits

This follow-up does not complete PX-003. Nmap/WHOIS/WhatWeb/HTTP/DNS/Nikto/TLS
packs, HTML/PDF parity, byte-decoding/oversize corpus cases and raw-JSONL byte
anchors remain deferred. Neither synthetic results nor CI sign off field use.
