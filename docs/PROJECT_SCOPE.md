# Named project scopes and approved assets (PX-101)

Manage named projects with explicit, exact target approvals instead of
re-entering isolated targets. The registry validates, previews, stores, and
lists approved scopes. On current `main`, the opt-in `scan --project NAME`
path enforces stored approval for the audited bounded adapters (HTTP headers,
DNS, TLS) and passive profile. Unsupported adapters are **blocked** for
project-bound scans rather than being run with unchecked redirects or extra
targets. There is still **no batch or scheduled scanning**.

```text
python penx.py project create acme
python penx.py project add acme --target example.test
python penx.py project add acme --target 192.168.0.0/30
python penx.py project add acme --target sub.example.test --as-candidate
python penx.py project add acme --target api.example.test --expiry 2026-12-31T00:00:00+00:00 --rate 20 --budget 5000 --tags prod,web
python penx.py project list
python penx.py project list acme
python penx.py project check acme --target example.test:443
python penx.py project preview acme
```

## Opt-in project-bound headless scans (PX-101 follow-up)

Examples below are **illustrative only**. `example.test` is not automatically
an authorized target; run the commands only for assets you control or have
explicit permission to assess.

```text
python penx.py project create owned-assessment
python penx.py project add owned-assessment --target example.test --rate 2 --budget 120
python penx.py scan --project owned-assessment --target example.test --scanners 4,5 --authorized --output ./reports
python penx.py scan --project owned-assessment --target https://example.test:8443 --scanners 4,d --authorized --output ./reports
python penx.py scan --project owned-assessment --target example.test --profile passive --authorized --output ./reports
```

- `--project` is **opt-in**; standalone `scan` keeps its previous explicit
  `--authorized`/active `--consent` behavior. Project registration does *not*
  replace operator authorization. A project-bound scan needs both flags when
  the selected adapters require them.
- A fresh database lookup checks approval before the first scanner and before
  **each** later adapter, with a second check in each worker. Passive collection
  rechecks before outbound provider requests. An expired/revoked/ambiguous
  grant, a candidate-only target, unreadable database or modified scan plan
  blocks further collection. In-flight I/O is cooperative; immediate revocation
  cannot retroactively cancel a blocking OS operation.
- Only a **single concrete host/IP** is accepted as a run target; wildcard and
  CIDR entries can authorize an individual host but cannot be passed for a
  subnet-wide scan. An ambiguous overlap between approved entries is denied.
  Port-specific approvals are allowed only with adapters preserving that port.
  DNS and passive lookups require a host without an explicit port.
- Project-bound adapters currently supported: `4` HTTP headers (HEAD/GET,
  redirects **not followed**), `5` DNS queries, `d` verified TLS handshake.
  The `passive` profile is also supported. All other adapters are **rejected
  before any network I/O or subprocess**, because their redirects, scanning
  fan-out or rate policy have not been proven safe under this project contract.
  This does not disable them for independent, explicitly authorized scans.
- A project's `--rate` is a **per-run rate ceiling on logical outbound calls** for the
  supported Python HTTP/DNS/TLS adapters and passive provider queries. It
  cannot constrain every underlying DNS socket retry or network packet and is
  not a global multi-process bandwidth/request rate limit. A per-run shared cooperative limiter applies
  between requests, including TLS retry and HEAD-to-GET fallback. Values above
  60 or ones whose dispatch interval exceeds the 60-second scheduler limit are
  refused, never silently ignored. External scanners without this control
  are blocked.
- `--budget` on the project asset means total seconds. The project budget is
  an **upper bound**, applied alongside the CLI budget and a 3600-second
  project-run ceiling (minimum supported budget: 30 seconds). Project-bound
  scans force one worker and an adapter dispatch interval no shorter than
  the request-rate cap; they never raise CLI/profile limits.
- `scan --dry-run --project NAME` validates the stored scope and budget but
  runs no scanner. There are no background jobs or automatic resumes.
- SQL migration is unchanged (SQLite v4; optional MariaDB migration 008).
  Approval reads use the configured storage backend; MariaDB acceptance is
  covered by integration CI, not a claim of physical Windows/Kali acceptance.

**Current limitations:** the authorization check and outbound request are not
one database transaction, so another process can revoke between check and a
blocking request. An in-flight scanner is not guaranteed to stop instantly.
Adapters with unverified follow-on behavior remain unavailable in this mode.
Human field acceptance (Windows/Npcap/Kali and real database restore) remains
separate from CI.

## Target kinds

`project add --target` accepts exactly one of the following, normalized to the
same canonical form the scanner adapters already accept:

| Kind | Example | Canonical | Notes |
| --- | --- | --- | --- |
| host | `example.test` | `example.test` | IDN folded to ASCII; case-insensitive |
| host:port | `example.test:8443` | `example.test:8443` | Port `1..65535` |
| IPv6 | `[2001:db8::1]:8443` | `[2001:db8::1]:8443` | Bracketed form preserves the port |
| URL | `https://example.test:8443` | `example.test:8443` | `http`/`https` only; no path, query, userinfo, or fragment |
| CIDR | `192.168.0.0/30` | `192.168.0.0/30` | Bounded to 256 addresses |
| wildcard | `*.example.test` | `*.example.test` | Exactly one extra label |

Whitespace, options, and scheme paths are rejected. A CIDR larger than 256
addresses is rejected, so internal-network expansion (`10.0.0.0/8`) cannot be
stored. Wildcards cannot carry a port.

## Authorization semantics

`project check` returns a boolean for one target against one project scope:

- A **host-level** approval (no port) authorizes any port on that host.
- A **port-specific** approval authorizes only that exact port.
- A **CIDR** approval authorizes the addresses inside its bounded network.
- A **wildcard** approval authorizes exactly one extra label
  (`sub.example.test` yes; `a.b.example.test` and `example.test` no).
- A target is authorized only while its asset is `approved` **and** not
  expired. An `approved_at`/`expiry` pair with `expiry <= approved_at` is
  rejected at write time.
- **Candidates** (`--as-candidate`) are never authorized until explicitly
  re-recorded as approved.
- An unparseable target is never authorized.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success, or `check` with an authorized target |
| `1` | `check` with a target that is **not** authorized |
| `2` | Usage, scope, or storage error (no scan dispatched) |

## Storage

Adds SQLite schema **v4** additively (fresh and legacy v2/v3 databases converge
on the same schema in one fail-closed transaction):

- `projects` (`id`, unique `name`, `created_at`)
- `project_assets` (`id`, `project_id`, `raw`, `canonical`, `kind`, `status`,
  `approved_at`, `expires_at`, `max_rate`, `max_budget`, `tags`), with a unique
  index on `(project_id, canonical, kind)`.

A project holds at most 1000 assets. Duplicate `(canonical, kind)` pairs are
rejected by the index; the service also checks before writing for a readable
error. The `status` column is `approved` or `candidate`; expiry is derived at
read time, so a row never silently flips status.

## Deferred (not in this release)

- Batch scanning over a project's assets.
- Automatic approval of discovered subdomains (they are candidates only).
- Project rate/budget enforcement for **external scanners**, which are
  deliberately blocked in project-bound mode pending audited controls.

### MariaDB setup

For an existing MariaDB installation, back up the database, then apply
`migrations/008_project_scopes.sql` after `007_summary_unique.sql`.
PenX intentionally does not auto-apply MariaDB DDL at startup.
The migration creates the same project and asset columns, uniqueness
constraints, and a foreign key; it does not scan, rename, or drop data.
The MariaDB CI workflow applies all numbered migrations to a disposable
database and exercises the real ProjectRepository CRUD contract.
