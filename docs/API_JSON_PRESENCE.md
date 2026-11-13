# PX-310 — Private JSON field presence for local API role comparison

Status: opt-in evidence refinement for the existing localhost-only API role/status
tool. NOT a confirmed BOLA/IDOR scanner, and NOT a production authorization
test. The standard api-role-compare command remains status-only with its
unchanged penx-api-role-matrix-v1 report.

## Example local manifest

    {
      "schema": "penx-api-role-plan-v1",
      "origin": "http://127.0.0.1:18123/",
      "cases": [
        {
          "path": "/api/me",
          "expect": {"guest": "deny", "user": "allow", "admin": "allow"},
          "protected_json_pointers": ["/data/accountId", "/data/owner"]
        }
      ]
    }

Each case requires 1..3 explicitly operator-selected object field pointers
(maximum 4 levels) for JSON mode. No wildcards, arrays, escaped pointers,
response-driven discovery, arbitrary paths or data values in the manifest.
Never put secret values into field names: the selected pointer names appear
in the report.

Provide distinct disposable test API tokens through
PENX_LAB_USER_TOKEN / PENX_LAB_ADMIN_TOKEN, as in API_ROLE_MATRIX.md.
PowerShell 7 command:

    python penx.py api-role-compare --plan .\lab-role-plan.json --authorized --consent --inspect-json --output-dir .\reports

Inspect-json must be explicitly enabled, and every case needs explicit
protected_json_pointers. If pointers are present without the flag, or the
flag is present without pointers, the request is refused before network I/O.

## Evidence and limitations

The report schema in this mode is penx-api-role-matrix-json-v1.
JSON field observations are restricted to present / absent / null / empty,
plus the parse state. Raw field values, body bytes, hashes, cookies and
tokens are not persisted.

Deny + 2xx + selected protected field present contributes a
protected_json_presence_leads count. It is an UNVERIFIED manual review
lead: an accountId-shaped field does not by itself prove cross-user data
access. Deny + 2xx with HTML/login response contributes no protected
JSON presence and makes coverage PARTIAL. Allow + 2xx without any selected
field is counted separately as allow_role_expected_fields_missing.

Only 2xx JSON responses are inspected transiently, max 16 KiB decoded
body per response, max 12 levels/200 nodes, 3 pointers/case.
Denied 401/403 and redirects are never body-inspected. The existing cap
of 6 exact literal paths x 3 roles = 18 local GET requests, no redirects,
no proxy and no DNS resolution is unchanged; no extra request is performed.
JSON duplicate keys, invalid bytes, oversized or unreadable responses
cannot produce a false confirmed finding.

The selected access policy and the protected nature of fields come
from the operator, not from independently verified evidence. All reports
retain vulnerability_verified=false, bola_idor_verified=false,
raw_json_values_persisted=false and scan_grant_transferable=false.
No active scanner, existing finding, SARIF policy, database, project
consent grant, third-party site or live shop is changed.

## Tests

    python -m unittest tests.test_private_json_role_review tests.test_api_role_matrix -v
    python offline_tests.py --keep-going
    python scripts/validate_distributions.py

Test cases use synthetic local fixtures only. Any external authenticated
API scanning, object-ID substitutions or verified BOLA oracle require a
separate design, explicit target/identity scope, privacy review and
independent operator field acceptance.

Rollback: revert the PX-310 PR. The default status-only v1 schema and
behaviour remain unchanged. No database migration or release is required.
