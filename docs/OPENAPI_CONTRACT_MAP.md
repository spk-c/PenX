# PX-308: Offline OpenAPI contract map

**Status: optional local declaration inventory.** This is NOT an API probe,
a vulnerability detector, an authenticated scan or consent to assess a host.
The new command does not perform any network request:

    python penx.py api-map --file ./my-openapi.json --output ./reports

The source must be an ordinary **local JSON** OpenAPI 3.0.x or 3.1.x
document (UTF-8, with or without a Windows-style UTF-8 BOM). The importer does not parse YAML, fetch URLs, dereference
references, install dependencies, invoke a model, or execute any declared
HTTP method. Only path templates, HTTP methods, query/path parameter
**names**, declared authentication, and declared scheme **types** remain.
Server URLs are counted but never used as network targets. The output
discards passwords, credentials, header/cookie parameter names, security
scheme details, examples, response bodies and request bodies.

## Output contract

The new, separately published JSON report (penx_openapi_contract*.json)
has schema penx-openapi-contract-map-v1:

- source_sha256 ties the map to the exact input bytes (not proof that the
  supplied contract is accurate or authorized).
- state is offline-declared-not-verified. Every route says
  source=openapi-declaration-not-observed and request_performed=false.
- Bounded route templates/methods, path/query **parameter names**,
  auth status (unspecified / none-declared / auth-declared / unresolved),
  auth_types_declared and deprecated.
- Counts for declared/mapped operations, ignored server entries,
  unresolved references, unknown fields, and truncated paths.
- network_requests=0, vulnerability_verified=false, scan_authorized=false.

A COMPLETE result means only that the **supported structural fields**
were parsed without recorded omissions. It does not confirm that an
endpoint exists, enforces authentication, is secure, or is authorized for
testing. PARTIAL covers unresolved references, unknown path fields,
more than 150 mapped paths, or no mappable operations. JSON parser
failures, dangerous path templates, invalid auth and oversized inputs
are rejected without publishing any report. No missing finding means safe.

## Limits and data handling

Local input is capped at 1 MiB and 300 path items. Output retains at
most 150 path templates and eight recognized method declarations per
path. Parameter lists and path/name grammars are bounded; percent
escapes, traversal segments, double slashes, query strings and URLs
are rejected as path templates. Duplicate JSON keys, non-finite
numbers, symlinks and unsupported OpenAPI versions are rejected.
External or local references are never followed, and explicitly
cause incomplete coverage.

Reports use exclusive publication without overwriting prior reports.
The original scan history and the active endpoint inventory remain
unchanged. **Path templates and parameter names may reveal private API
structure**: keep reports local, review before sharing and do not put
real credentials in template paths.

## Relation to existing PenX scanners

The existing scanners/endpoint_inventory.py module tracks real scanner
observations and attributed Katana/ffuf sources. This new module is
separate: OpenAPI declarations must never be represented as observed
endpoints or silently fed into scanner follow-up path lists.

Future live API scanning requires separately reviewed exact-scope and
role authorization, method-side-effect controls, credential containment,
synthetic test coverage and independent operator field acceptance.
None is enabled by this patch.

## Verification

    python -m unittest tests.test_openapi_contract_map -v
    python offline_tests.py --keep-going
    python scripts/validate_distributions.py

Tests use synthetic contracts, malicious server URLs, malformed JSON,
security alternatives, truncation, no network/subprocess execution and
exclusive outputs. They do not establish real API vulnerability
detection.

**Rollback:** Revert this PR to remove the opt-in CLI and standalone
report schema. There are no migrations, release changes, new runtime
dependencies or active scanner permission changes.
