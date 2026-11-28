# PX-305 — Local configuration/IaC linting

**Status:** Optional, **read-only** offline linting of user-supplied
nginx/Apache/TLS policy, Docker Compose and Kubernetes/IaC files. No shell
execution of configuration, no network access, no credential interpretation.

`penx config lint` reads a single local file, classifies its format with a
bounded, deterministic, line-based parser and prints a stable JSON report.
The linter never executes the configuration, never opens a network connection,
and never interprets or stores credentials; it only reports explicit,
unambiguous weak settings.

## Usage

~~~bash
python penx.py config lint --file ./nginx.conf
python penx.py config lint --file ./docker-compose.yml
python penx.py config lint --file ./policy.json
~~~

The file must be an ordinary, readable, UTF-8 text file of at most 1 MiB. The
command is fully offline and non-interactive.

## Supported formats and rules

| Format | Detected by | Rules |
| --- | --- | --- |
| nginx | `events {`, `http {`, `server {` | `NGINX_SSLV1`, `NGINX_SSL_CIPHERS`, `NGINX_ALLOW_ALL`, `NGINX_SERVER_TOKENS_ON` |
| Apache | `<directory`, `<virtualhost`, `<location`, `ServerTokens` | `APACHE_INDEXES`, `APACHE_SERVER_TOKENS`, `APACHE_TRACE_ON` |
| Docker Compose | `services:` | `YAML_PRIVILEGED`, `YAML_ROOT_USER`, `YAML_HOST_MOUNT`, `YAML_ALL_INTERFACE_PORT`, `YAML_ENV_SECRET` |
| k8s / IaC | `apiVersion:` + `kind:` | same YAML rules as Docker Compose |
| TLS policy | JSON with `protocols`/`ciphers`/`ssl_protocols`/`ssl_ciphers` | `TLS_PROTOCOL`, `TLS_CIPHER` |

Unrecognized files are reported as `format: unknown`, `coverage: PARTIAL` with
no findings and an explanatory limitation.

## Report schema

`penx-config-lint-v1`. Every finding carries a stable rule ID, severity, line
number and the exact (truncated) source line as evidence:

~~~json
{
  "schema": "penx-config-lint-v1",
  "format": "nginx",
  "source": "./nginx.conf",
  "source_sha256": "...",
  "line_count": 8,
  "byte_size": 134,
  "coverage": "COMPLETE",
  "findings": [
    {
      "rule_id": "NGINX_SSLV1",
      "severity": "high",
      "line": 4,
      "message": "Weak TLS protocol enabled (TLSv1/TLSv1.1)",
      "evidence": "ssl_protocols TLSv1 TLSv1.1 TLSv1.2;"
    }
  ],
  "limitations": [
    "Rules are heuristic and source-based; findings are observations, not exploitability proofs."
  ],
  "network_access": false
}
~~~

## Bounded, fail-closed input handling

- At most 1 MiB; larger inputs are rejected before reading.
- Symlinks, FIFOs, directories and non-regular files are rejected; the file is
  opened with `O_NOFOLLOW` and the inode identity is re-checked after open to
  reject link/replacement races.
- Non-UTF-8 input is rejected; no report is produced for unreadable input.
- No YAML library is used, so aliases and self-referencing anchors are never
  expanded (no billion-laughs / recursive-alias crash).

## Security properties

- **Read-only and offline:** never executes configuration, opens no network
  connection, and performs no subprocess.
- **Secret-safe:** environment variables that look like secrets (e.g.
  `API_KEY=...`, `DB_PASSWORD=...`) are reported by name only and the value is
  redacted to `***`. `${...}` references and non-string values are not flagged.
- Findings are observations, not exploitability proofs; `network_access` is
  always `false`.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Lint succeeded; JSON report printed (with or without findings) |
| 2 | Input invalid/unreadable (missing, non-UTF-8, too large, symlink, directory) or unrecognized arguments; JSON `status: unverified` printed |

Findings do not cause a non-zero exit; `config lint` is an informational,
offline linter, not a CI gate.

## Tests

~~~powershell
python -m unittest tests.test_local_config -v
python offline_tests.py --keep-going
python scripts/validate_distributions.py
~~~

Tests use local temporary files and synthetic fixtures only; no CI test reads
a real configuration or connects to any target.

**Rollback:** Revert the PX-305 PR; no persistent schema, scanner registry,
adapter consent, or runtime dependency has changed.
