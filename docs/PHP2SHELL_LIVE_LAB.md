# PHP2Shell live header assessment: isolated lab

## Goal and safety

Validate the **non-exploiting** PHP2Shell live-scan code with local mock HTTP
responses. This test does not install an affected PHP interpreter, trigger
memory exhaustion, send multipart payloads, launch a shell, or demonstrate
actual CVE exploitation. A forged header can never attest patch status.

## Reproducible offline test

From a PenX source checkout, install project test dependencies as described
in the development guide and run:

```sh
python -m unittest discover -s tests -p 'test_php2shell_live_http.py' -v
```

The suite includes an actual loopback HTTP server bound to `127.0.0.1` and asserts exactly **one HEAD**, no GET/POST and no exploit payload. It also mocks an authorized live HTTP HEAD response containing
`X-Powered-By: PHP/8.4.26`, verifies that it is flagged
`POTENTIALLY_VULNERABLE` and requires no additional GET/POST requests.
It also checks patched-looking, missing and inconsistent headers, expected
HEAD-to-GET fallback, JSON and SARIF exports, and no confirmed RCE claims.

## Production live scan

Run PenX, choose a system you own or are authorized to assess, and select
`[a] Standard Scan` (or another scan containing `[4] HTTP headers`).
The tool prints `[PENX PHP2SHELL LIVE] POTENTIALLY_VULNERABLE` when a
single exposed PHP version predates the upstream fix; otherwise it prints
`UNVERIFIED`. This happens within the existing HEAD/GET request budget.

## Patch verification on a server you control

Check the **actual PHP web worker** and the vendor-managed package metadata
using privileged, authenticated maintenance access (for example your SSH
administration session). Ensure that the running PHP-FPM pools/web SAPI
use the patched packages, check vendor-specific backport advisories, then
restart and verify the workers. CLI `php -v` alone does not establish what
the HTTP-serving PHP SAPI runs. An exposed X-Powered-By header may be
hidden, spoofed, or supplied by a reverse proxy. PenX will *not* label
the server `PATCH_VERIFIED` without independent authenticated evidence.

PHP2Shell-related CVEs: CVE-2026-109618, CVE-2026-109619.
Source: https://www.php.net/
