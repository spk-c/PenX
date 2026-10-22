# Typed scanner configuration and custom profiles

Export a built-in profile, edit its explicit settings and validate it offline:

```text
python penx.py profiles --export standard --output ./profiles
python penx.py profiles --validate ./profiles/standard.profile.json
python penx.py profiles --copy ./profiles/my-profile.json --output ./profiles
python penx.py scan --target example.test --authorized --profile-file ./profiles/my-profile.json --format both
```

`--copy` validates and canonically exports a custom profile under a unique name;
existing files are never overwritten. Profile files are limited to 64 KiB.
Unknown fields, duplicate JSON keys, invalid versions, booleans in numeric
fields, non-finite numbers and unselected/duplicate scanner options are rejected
before adapter execution. Profiles store neither targets nor consent: the caller
must supply both at execution time. There are no profile fields for credentials,
environment variables, headers, executable/template paths or raw command flags.

The version-1 document contains exactly `schema_version`, `profile_id`,
`profile_version`, `scanner_keys`, `passive_only`, `scanner_configuration`,
`max_parallelism`, `global_budget_seconds`, and `dispatch_interval_seconds`.
An optional `dependencies` array contains `[dependent_key, prerequisite_key]`
pairs. Both keys must already be selected. Cycles, self-edges, duplicates and
references outside the selection are rejected. Execution uses stable topological
ordering and waits for prerequisite completion, including actual worker exit.
Failed/partial prerequisites skip their descendants while independent work
continues. Dependency snapshots appear in metadata, reports and comparisons.

Example `scanner_configuration` (keys must also appear in `scanner_keys`):

```json
[
  {"scanner_key": "1", "timeout_seconds": 120, "ports": [80, 443]},
  {"scanner_key": "7", "timeout_seconds": 180, "severities": ["high", "critical"], "rate_limit": 1}
]
```

| Option | Scope | Bound |
| --- | --- | --- |
| `timeout_seconds` | Every registered adapter | Integer, 30–900 seconds |
| `ports` | Nmap (`1`) | Up to 100 unique integers, 1–65535 |
| `severities` | Nuclei (`7`) | Subset of low/medium/high/critical |
| `rate_limit` | Nuclei (`7`), httpx (`8`), ffuf (`9`) | Integer requests/second, at most 2/3/2 respectively |

Optional array fields default to empty and optional numeric fields to null.
Rate limits can only preserve or lower existing defaults. Fixed scanner safety
flags, non-interactive behavior and original target arguments remain enforced.
Custom ports change the explicitly requested service coverage, never the target
host. Scanner discoveries are not automatically added to scope.

Profiles/headless execution permit at most 8 workers and a global budget of
30–3600 seconds (or null). Dispatch intervals must be finite, positive and at
most 60 seconds. Headless passive providers support budgets and dispatch
intervals but run sequentially; active-adapter configuration/dependencies are
not valid in a passive profile.

Typed profile timeouts override environment/default timeouts for subprocesses
and node scheduling. Explicit `ScanPlan.per_scanner_timeouts` take precedence
over duplicate typed timeout values. Network-library calls retain their bounded
adapter I/O timeouts and observe cooperative cancellation at their existing
checkpoints; Python threads cannot be forcibly killed. Timed-out workers retain
their slot until they actually exit. Each node receives its own deadline signal;
the global budget signals all running nodes even after the final dispatch.
Dispatch waits recheck cancellation and budget before starting more work.

Options are bound inside each worker through a context-local value rather than
mutating global environment variables. With no configured options, legacy
sequential execution and metadata remain compatible. Configured execution
persists an allowlisted snapshot in additive metadata v3 and exposes it in
headless reports and comparisons, including explicit configuration differences.
