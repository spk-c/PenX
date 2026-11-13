# PX-309 — Loopback API role/status comparison

**Status:** Explicitly opt-in, disposable local-lab **GET/status-only**
authorization-policy consistency comparison. Not a production API scanner,
not verified BOLA/IDOR detection, not an authenticated general web crawler.

The default mode remains status-only and does not read response bodies.
An optional strictly local JSON-field presence mode is documented in
[API_JSON_PRESENCE.md](API_JSON_PRESENCE.md), and requires the explicit
--inspect-json flag plus selected protected_json_pointers in each case.

This first slice takes only operator-authored paths, a declared role policy,
and two **disposable** bearer tokens for the local synthetic API under test.
It never imports real credentials, follows discovered URLs, tests external
hosts, changes object IDs, sends POST/PUT/PATCH/DELETE, executes model output,
loads response bodies, or promotes results into existing PenX findings.

## Explicit local manifest

Create a local JSON file (example: lab-role-plan.json):

~~~json
{
  "schema": "penx-api-role-plan-v1",
  "origin": "http://127.0.0.1:18123/",
  "cases": [
    {
      "path": "/api/me",
      "expect": {"guest": "deny", "user": "allow", "admin": "allow"}
    },
    {
      "path": "/api/admin",
      "expect": {"guest": "deny", "user": "deny", "admin": "allow"}
    }
  ]
}
~~~

The paths must be literal, explicitly selected and owned; no placeholders,
queries or arbitrary URLs. Even nominally read-only GET endpoints may change
server state. Use **only** disposable test data and a test service you own.

Supply the synthetic API's separate disposable bearer tokens through
environment variables (not CLI args or JSON files). In PowerShell:

~~~powershell
$env:PENX_LAB_USER_TOKEN = Read-Host -MaskInput "Disposable user token"
$env:PENX_LAB_ADMIN_TOKEN = Read-Host -MaskInput "Disposable admin token"
python penx.py api-role-compare --plan ./lab-role-plan.json --authorized --consent --output-dir ./reports
Remove-Item Env:PENX_LAB_USER_TOKEN,Env:PENX_LAB_ADMIN_TOKEN
~~~

The masked prompts require PowerShell 7. Do not paste tokens into shell
history; the process environment is still readable by sufficiently
privileged local processes. In Bash, provide these variables via your
local test harness rather than
saving them in the plan. Do not use production session tokens. The two
values must be different; missing tokens or malformed headers fail before
the first request. An explicit 32-KiB JSON plan, confirmed authorization,
explicit consent and a literal IP loopback URL are mandatory.

## Strictly bounded behavior

- **Up to 6 operator-specified paths x 3 roles = 18 GET requests**.
- Only http(s)://127.0.0.1:PORT/ or http(s)://[::1]:PORT/.
  No domain names, LAN IPs, proxies, redirects, cross-origin hops or DNS.
- No query strings, path templates, percent decoding, path traversal,
  unsafe route verbs, or dynamic substitutions.
- Fresh HTTP session per role/request, environment proxy/netrc disabled,
  cookies not reused, redirects forbidden, TLS certificate verification on.
- 2–20 second configured per-request I/O timeout (default 5), total
  request budget 10–120 seconds (default 60). Total budget is checked
  before each request, but socket read timeouts are not hard real-time
  cancellation and may exceed the remaining wall-clock budget.
- Guest requests have no Authorization header; user and admin use distinct
  disposable Bearer tokens from environment. No OAuth refresh, SSO,
  session discovery, browser profile import or auto-login.
- Responses are **never read beyond the status line/headers**. No response
  body, cookie, redirect URL, credential, token or raw header is written
  to results. Each response is closed immediately.

## Interpretation (not vulnerability proof)

Output file: penx_api_role_comparison*.json (exclusive, separate report).
Each case records only path, GET method, expected policy per role, HTTP
status and a bounded comparison category:

| Comparison | Meaning |
| --- | --- |
| matches-declared-policy | allow + 2xx, or deny + 401/403 |
| possible-excess-access | deny + 2xx; **manual review required** |
| unexpected-denial | allow + 401/403; policy or fixture inconsistency |
| inconclusive | redirect, 404, rate limit, server error, etc. |
| transport-error | connection/timeouts failed; **not a secure finding** |
| budget-exhausted | no request was made for that role |

Status 200 may return a login page or error object, so an unexpected 2xx
does **not** prove unauthorized data was actually disclosed. Status 403
does **not** prove robust protection across all paths or object IDs.
The manifest's declared expectation is operator-provided; it is not an
independently verified access-control policy.

Results always retain vulnerability_verified=false,
bola_idor_verified=false, response_bodies_collected=false and
scan_grant_transferable=false. Coverage COMPLETE means all selected
requests returned useful HTTP statuses; it is *not* security completeness.
PARTIAL indicates at least one inconclusive or missing response.
Exit 0 means all selected policy checks matched. Exit 1 means possible
excess access, unexpected denial or incomplete coverage. Exit 2 means
the local plan/permissions/tokens/run is invalid or unavailable. No
result automatically modifies existing PenX scanner results or SARIF.

### Security and acceptance

The implementation does not independently prove the owner of a local
loopback process. A malicious program listening on the explicitly selected
local port could receive disposable credentials. Never reuse real tokens.
The status-only comparison cannot claim verified cross-tenant data access,
authenticated BOLA/IDOR coverage, CSRF posture or exploitability.

An independent production/API field assessment requires explicit exact
target and identity scope, reviewed credential handling, safe method
semantics, object-level authorization oracle, response-content comparison
with privacy controls and separate human approval. None of that is
implicitly enabled by this proof-of-concept.

## Tests

~~~powershell
python -m unittest tests.test_api_role_matrix -v
python offline_tests.py --keep-going
python scripts/validate_distributions.py
~~~

Tests exercise fake HTTP clients and local synthetic data only; no
CI test invokes any external target. Optional real loopback smoke uses
an ephemeral owned fixture server, never a production application.

**Rollback:** Revert the PX-309 PR; no persistent schema, API adapter
registry, scanner consent, or runtime dependency has changed.
