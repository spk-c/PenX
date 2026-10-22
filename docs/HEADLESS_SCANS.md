# Headless scans and CI policy

Run only against an explicitly authorized target:

```text
python penx.py scan --target example.test --authorized --profile standard --output ./reports --format both
python penx.py scan --target example.test --authorized --scanners 7 --consent --fail-on high --format sarif
python penx.py scan --target example.test --profile standard --dry-run
```

`--authorized` confirms permission for the exact target; consent-gated scanners
additionally require `--consent`. Profile and explicit scanner selection are
mutually exclusive. The existing planner enforces budgets, dispatch intervals,
parallelism, cancellation and consent. Options: `--budget SECONDS`,
`--max-parallelism N`, `--dispatch-interval SECONDS`, `--redact` and optional
`--raw-artifacts PRIVATE_DIRECTORY`. Dry-run probes local scanner availability
without network collection or an authorization assertion.

Collection works without an AI endpoint, model, database or prompts. It writes
`penx_scan.json` and/or `penx_scan.sarif` atomically, choosing unique names on
repeated runs. It does not create a saved assessment session. JSON uses the
separate `penx-scan-v1` schema so collection cannot be confused with a reviewed
`penx-assessment-v1` export. Both standalone schemas are in `docs/schemas/`.

Explicit Nuclei matches, HTTP HSTS-disable/PHP-version observations and verified
TLS certificates nearing expiry produce conservatively rated findings. Nmap
open services and structured Nikto observations are informational. Remaining
adapters provide collection coverage, not automatic security verdicts. A match
remains a hypothesis requiring applicability review. A clean
exit means collection/policy passed, never proof of absence of vulnerabilities.
Headless passive collection uses typed DNS/CT/RDAP and public-IP InternetDB
providers, with no active target adapter or paid API. It supports cooperative
cancellation, global budget and provider dispatch intervals, running sequentially.
Each provider has a 15-second deadline; DNS/HTTP inactivity timeouts are at most
one second. Checks occur before/after I/O and between response chunks. These are
cooperative bounds, not forcible thread termination. Failed, cancelled and
truncated provider outcomes remain distinct from successful external lookups.
Successful provider coverage never proves target reachability or security.
The original interactive passive API is retained for compatibility.
`PENX_SHODAN_INTERNETDB=off` is respected by the headless provider selection.

| Exit | Meaning |
| --- | --- |
| 0 | Collection complete and configured finding policy passed |
| 1 | Unexpected runtime or report publication failure |
| 2 | Usage, scope, plan, authorization or consent error; no scan dispatched |
| 3 | At least one rated finding meets `--fail-on` threshold |
| 4 | A scanner failed (or dry-run found missing prerequisites) |
| 5 | Partial/unknown coverage, cancellation or interruption |

Scanner failures take precedence over incomplete coverage, which takes
precedence over finding policy. Reports are written for normal scanner failures
and partial outcomes; an emergency interrupt or report-write error can prevent
publication. `--fail-on info|low|medium|high|critical` is opt-in and considers
deterministic findings at or above the threshold. Findings remain in SARIF regardless
of policy exit. Stable `partialFingerprints` support SARIF result correlation.

`.github/workflows/authorized-scan.yml` is an optional manual-only workflow,
never a PR-triggered network scan. It requires an explicit authorization input,
defaults to binary-free HTTP/DNS/TLS adapters, preserves the collection exit code
after optional SARIF upload, and exposes the severity threshold as an input.
Additional scanner binaries must be installed on the runner before selecting
them. GitHub code scanning upload availability depends on repository settings.
Text redaction applies to reports; scanner progress logs and separately retained
raw artifacts can still contain unredacted target data.
