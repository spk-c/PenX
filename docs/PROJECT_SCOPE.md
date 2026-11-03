# Named project scopes and approved assets (PX-101)

Manage named projects with explicit, exact target approvals instead of
re-entering isolated targets. This release validates, previews, stores, and
lists approved scopes; it does **not** dispatch batch scanning. Approval
enforcement across a project's assets is deferred until it is proven.

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
- Rate/budget **enforcement** at dispatch time (values are stored, not yet
  applied).
