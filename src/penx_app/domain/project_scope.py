"""Pure named project scope and exact-approval contract (PX-101).

Domain-pure: no CLI, storage, network, or subprocess. Reuses the existing
target normalization (IDN, IPv6, bounded CIDR, ports) so a stored scope matches
exactly what the scanner adapters accept. Authorization is exact: only the
canonical form an operator explicitly approved may run. Discovered targets are
recorded as candidates and are never implicitly authorized.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from urllib.parse import urlsplit

from penx_app.scanners.scanner_targets import MAX_CIDR_ADDRESSES, normalize_host


class TargetKind(str, Enum):
    HOST = 'host'          # exact host/IP, optional explicit port
    CIDR = 'cidr'          # bounded IP network (<= MAX_CIDR_ADDRESSES hosts)
    WILDCARD = 'wildcard'  # strict '*.suffix' (exactly one extra label)


class AssetStatus(str, Enum):
    APPROVED = 'approved'
    CANDIDATE = 'candidate'  # discovered; never authorized until approved
    EXPIRED = 'expired'


MAX_ASSETS = 1000
MAX_NAME_LENGTH = 128
MAX_TAGS = 16
MAX_TAG_LENGTH = 64


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _require_aware(value: datetime, field: str) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ValueError(f'{field} must be a timezone-aware UTC datetime.')


def _authority(host: str, port: int | None) -> str:
    if port is None:
        return host
    if ':' in host:
        return f'[{host}]:{port}'
    return f'{host}:{port}'


def _split_authority(value: str) -> tuple[str, int | None]:
    """Split a scheme-less authority into (host, port), preserving brackets."""
    if value.startswith('['):
        end = value.find(']')
        if end == -1:
            raise ValueError('Invalid bracketed IPv6 address.')
        host = value[1:end]
        rest = value[end + 1:]
        if rest:
            if not rest.startswith(':') or not rest[1:].isdigit() or not 1 <= int(rest[1:]) <= 65535:
                raise ValueError('Invalid host port.')
            return host, int(rest[1:])
        return host, None
    if value.count(':') == 1:
        host, _, port = value.partition(':')
        if not port.isdigit() or not 1 <= int(port) <= 65535:
            raise ValueError('Invalid host port.')
        return host, int(port)
    if value.count(':') > 1:
        return value, None  # bare IPv6 literal, no port
    return value, None


def canonicalize(raw: str) -> tuple[TargetKind, str]:
    """Classify and canonicalize one scope target without network I/O.

    Scheme is optional and dropped; path/query are rejected so a scope stays at
    host:port granularity. Returns ``(kind, canonical)``.
    """
    value = raw.strip()
    if not value or any(c.isspace() for c in value) or value.startswith('-'):
        raise ValueError('Enter a valid target (no whitespace or options).')
    if value.startswith('*.'):
        suffix = value[2:]
        if not suffix or suffix.startswith('*.') or '.' not in suffix:
            raise ValueError('Wildcard must be one label before a domain.')
        if ':' in suffix:
            raise ValueError('Wildcard targets cannot include a port.')
        return TargetKind.WILDCARD, '*.' + normalize_host(suffix)
    if '://' in value:
        parsed = urlsplit(value)
        if parsed.scheme not in ('http', 'https') or not parsed.hostname:
            raise ValueError('Only http:// or https:// URLs are accepted.')
        if parsed.username is not None or parsed.password is not None or parsed.fragment:
            raise ValueError('Userinfo and URL fragments are unsupported.')
        if parsed.path not in ('', '/') or parsed.query:
            raise ValueError('Scope targets are host:port, not URLs with paths.')
        try:
            port = parsed.port
        except ValueError:
            raise ValueError('Invalid URL port.') from None
        if port is not None and (port == 0 or parsed.netloc.endswith(':')):
            raise ValueError('Invalid URL port.')
        return TargetKind.HOST, _authority(normalize_host(parsed.hostname), port)
    if '/' in value:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise ValueError('Invalid IP/CIDR subnet.') from exc
        if network.num_addresses > MAX_CIDR_ADDRESSES:
            raise ValueError(
                f'CIDR target too large for a project asset '
                f'(maximum {MAX_CIDR_ADDRESSES} addresses).')
        return TargetKind.CIDR, str(network)
    host, port = _split_authority(value)
    return TargetKind.HOST, _authority(normalize_host(host), port)


def _wildcard_matches(host: str, suffix: str) -> bool:
    if not host.endswith('.' + suffix):
        return False
    label = host[: -(len(suffix) + 1)]
    return label != '' and '.' not in label


def _host_matches(approved: str, host: str, port: int | None) -> bool:
    approved_host, approved_port = _split_authority(approved)
    if approved_host != host:
        return False
    return approved_port is None or approved_port == port


@dataclass(frozen=True)
class Asset:
    raw: str
    canonical: str
    kind: TargetKind
    approved_at: datetime
    expires_at: datetime | None = None
    max_rate: float | None = None
    max_budget: int | None = None
    tags: tuple[str, ...] = ()
    status: AssetStatus = AssetStatus.APPROVED

    def __post_init__(self):
        if not isinstance(self.raw, str) or not self.raw.strip():
            raise ValueError('Asset raw target must be non-empty.')
        if self.kind not in (TargetKind.HOST, TargetKind.CIDR, TargetKind.WILDCARD):
            raise ValueError('Invalid asset kind.')
        if not isinstance(self.canonical, str) or not self.canonical:
            raise ValueError('Asset canonical must be non-empty.')
        _require_aware(self.approved_at, 'approved_at')
        if self.expires_at is not None:
            _require_aware(self.expires_at, 'expires_at')
            if self.expires_at <= self.approved_at:
                raise ValueError('Asset expiry must be after approval.')
        if self.max_rate is not None and (
                isinstance(self.max_rate, bool) or not isinstance(self.max_rate, (int, float))
                or self.max_rate <= 0):
            raise ValueError('Asset max rate must be a positive number.')
        if self.max_budget is not None and (
                isinstance(self.max_budget, bool) or not isinstance(self.max_budget, int)
                or self.max_budget <= 0):
            raise ValueError('Asset max budget must be a positive integer.')
        if not isinstance(self.tags, tuple) or len(self.tags) > MAX_TAGS:
            raise ValueError('Asset tags must be a bounded tuple.')
        for tag in self.tags:
            if not isinstance(tag, str) or not 1 <= len(tag) <= MAX_TAG_LENGTH:
                raise ValueError('Asset tags must be bounded strings.')
        if self.status not in (AssetStatus.APPROVED, AssetStatus.CANDIDATE, AssetStatus.EXPIRED):
            raise ValueError('Invalid asset status.')


@dataclass(frozen=True)
class ProjectScope:
    name: str
    created_at: datetime
    assets: tuple[Asset, ...] = ()

    def __post_init__(self):
        if not isinstance(self.name, str) or not 1 <= len(self.name) <= MAX_NAME_LENGTH:
            raise ValueError('Project name must be 1..128 characters.')
        _require_aware(self.created_at, 'created_at')
        if not isinstance(self.assets, tuple):
            raise ValueError('Project assets must be a tuple.')
        if len(self.assets) > MAX_ASSETS:
            raise ValueError('Too many project assets.')
        seen = set()
        for asset in self.assets:
            if not isinstance(asset, Asset):
                raise ValueError('Project assets must be Asset records.')
            key = (asset.kind, asset.canonical)
            if key in seen:
                raise ValueError('Duplicate project asset.')
            seen.add(key)


def is_expired(asset: Asset, now: datetime | None = None) -> bool:
    now = now or _utc_now()
    return asset.expires_at is not None and now >= asset.expires_at


def authorize(scope: ProjectScope, target: str, *, now: datetime | None = None) -> bool:
    """True only when ``target`` is an exact, non-expired, approved asset.

    A host-level approval (no port) covers any port on that host; a port-specific
    approval covers only that port. A wildcard covers exactly one extra label.
    A CIDR covers the addresses inside its bounded network. Candidates never
    authorize; an unparseable target is never authorized.
    """
    now = now or _utc_now()
    try:
        kind, canonical = canonicalize(target)
    except ValueError:
        return False
    target_host = None
    target_port: int | None = None
    if kind is TargetKind.HOST:
        target_host, target_port = _split_authority(canonical)
    for asset in scope.assets:
        if asset.status is not AssetStatus.APPROVED or is_expired(asset, now):
            continue
        if asset.kind is TargetKind.CIDR:
            if kind is TargetKind.CIDR and asset.canonical == canonical:
                return True
            if kind is TargetKind.HOST and target_host is not None:
                try:
                    if ipaddress.ip_address(target_host) in ipaddress.ip_network(asset.canonical):
                        return True
                except (ValueError, TypeError):
                    continue
        elif asset.kind is TargetKind.WILDCARD:
            if kind is TargetKind.HOST and target_host is not None and _wildcard_matches(
                    target_host, asset.canonical[2:]):
                return True
        elif kind is TargetKind.HOST and target_host is not None and _host_matches(
                asset.canonical, target_host, target_port):
            return True
    return False


def expand_cidr_preview(canonical: str, *, limit: int = 32) -> dict:
    """Bounded preview of a CIDR asset: total count plus a bounded sample."""
    network = ipaddress.ip_network(canonical)
    if network.num_addresses > MAX_CIDR_ADDRESSES:
        raise ValueError('CIDR target too large for a project asset.')
    addresses = [str(address) for address in network]
    return {
        'canonical': str(network),
        'total': network.num_addresses,
        'truncated': len(addresses) > limit,
        'sample': addresses[:limit],
    }


def with_candidate(scope: ProjectScope, raw: str, discovered_at: datetime) -> ProjectScope:
    """Return a copy of ``scope`` recording ``raw`` as a CANDIDATE asset.

    Candidates are never authorized; they must be approved separately. Re-adding
    an already recorded canonical is idempotent.
    """
    kind, canonical = canonicalize(raw)
    for asset in scope.assets:
        if asset.kind is kind and asset.canonical == canonical:
            return scope
    candidate = Asset(raw=raw, canonical=canonical, kind=kind,
                      approved_at=discovered_at, status=AssetStatus.CANDIDATE)
    return ProjectScope(scope.name, scope.created_at, scope.assets + (candidate,))
