"""Opt-in fail-closed project authorization for one headless scan.

No implicit authorization: --authorized and the legacy active-consent gates
remain mandatory. Project approval is reloaded immediately before each adapter
and passive provider, without enabling any batch scanning.
"""
from __future__ import annotations

from dataclasses import dataclass
from dataclasses import replace
import ipaddress

from penx_app.application.project_service import ProjectService
from penx_app.domain.project_scope import Asset, canonicalize, matching_approved_assets
from penx_app.domain.scan_plan import ScanPlan, assert_valid_plan
from penx_app.scanners.project_rate import ProjectRateLimiter


# These audited adapters do not traverse a remote HTTP redirect and never
# expand beyond the approved target. Reject other adapters until their
# external process/redirect behavior is proven. Existing standalone scans
# are unaffected.
PROJECT_SAFE_SCANNERS = frozenset({'4', '5', '8', 'd'})
# Explicit inventory of currently disabled project-bound adapters. Adding a
# scanner to the tools menu must require a deliberate review decision instead
# of quietly making it accessible under persistent project authorization.
# 2 (WHOIS) performs registry requests and is blocked too, even though it is
# often omitted from lists of active external scanner processes.
PROJECT_REVIEW_REQUIRED_SCANNERS = frozenset({'1', '2', '3', '6', '7', '9', 'e', 's', 'c'})
# DNS works only on hostname, not a host-specific port. The direct
# HTTPS/TLS and httpx adapters honor explicitly specified URL port values.
PROJECT_PORT_SCANNERS = frozenset({'4', '8', 'd'})


class ProjectScopeDenied(ValueError):
    """Storage/scope denial must stop collection, not become evidence."""


@dataclass
class ProjectDispatchPolicy:
    name: str
    service: ProjectService
    _approved: Asset | None = None
    rate_limiter: ProjectRateLimiter | None = None
    _accepted_plan: ScanPlan | None = None

    def check(self, target: str) -> Asset:
        """Fresh storage read; missing/changed/revoked grants raise before I/O."""
        try:
            scope = self.service.scope(self.name)
            matches = matching_approved_assets(scope, target)
        except Exception as exc:
            raise ProjectScopeDenied('Project approval unavailable or target invalid.') from exc
        if len(matches) != 1:
            raise ProjectScopeDenied('Project target denied: missing or ambiguous approval.')
        asset = matches[0]
        if self._approved is not None and asset != self._approved:
            raise ProjectScopeDenied('Project approval changed during the scan.')
        return asset

    def ensure_prepared(self, plan: ScanPlan) -> None:
        """Reject direct library dispatches that bypass policy preparation."""
        if self._approved is None or self._accepted_plan != plan:
            raise ProjectScopeDenied('Project scan plan not approved or was modified.')

    def prepare(self, plan: ScanPlan) -> ScanPlan:
        """Apply no-expansion limits, then pin the approval for rechecking."""
        if self._approved is not None:
            raise ValueError('Project policy cannot be reused across scan plans.')
        # Parse only concrete, scope-approved hosts; reject wildcard/CIDR target
        # expansions even when those assets exist in the registry.
        kind, canonical = canonicalize(plan.target)
        if kind.value != 'host':
            raise ValueError('Project scanning requires a single host or IP.')
        if plan.passive_only:
            # Bare IPv6 is valid for passive lookups; '[::1]:443' is not.
            if canonical.startswith('[') or (canonical.count(':') == 1):
                raise ValueError('Passive project scans require a host without a port.')
            if ':' in canonical:
                ipaddress.IPv6Address(canonical)
        else:
            unsupported = set(plan.scanner_keys) - PROJECT_SAFE_SCANNERS
            if unsupported:
                raise ValueError('Project scan blocks scanners without verified scope containment: '
                                 + ', '.join(sorted(unsupported)))
            explicit_port = (canonical.startswith('[') and ']:' in canonical
                             or not canonical.startswith('[') and canonical.count(':') == 1)
            if explicit_port and any(key not in PROJECT_PORT_SCANNERS for key in plan.scanner_keys):
                raise ValueError('Selected project scanner does not preserve approved port.')
        asset = self.check(plan.target)
        budget = min(plan.global_budget_seconds
                     if plan.global_budget_seconds is not None else 3600, 3600)
        if asset.max_budget is not None:
            if asset.max_budget < 30:
                raise ValueError('Project budget below the supported 30-second minimum.')
            budget = min(budget, asset.max_budget)
        # Scoped adapter set is deliberately sequential: policy is re-read
        # before each dispatch, and a shared rate limiter is deterministic.
        interval = plan.dispatch_interval_seconds
        if asset.max_rate is not None:
            if asset.max_rate > 60:
                # Rate cap > 60 requests/s is a no-op relative to conservative
                # internal adapters, but limit to a verified implementation band.
                raise ValueError('Project rate must be <= 60 requests/second.')
            interval = max(interval or 0, 1.0 / asset.max_rate)
        restricted = replace(plan, max_parallelism=1,
                             global_budget_seconds=budget,
                             dispatch_interval_seconds=interval)
        assert_valid_plan(restricted)
        self.rate_limiter = (ProjectRateLimiter(asset.max_rate)
                             if asset.max_rate is not None else None)
        self._approved = asset
        self._accepted_plan = restricted
        return restricted
