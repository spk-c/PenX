"""Scan profile registry v1 and deterministic plan builders.

Profiles are declarative, versioned presets that map onto the P1-1
`ScanPlan` contract. Built-in entries never schedule consent keys without
the caller providing `active_consent`; plan validation (R1..R10) always
applies. The existing interactive menu presets ('0'/'a'/'n'/'x') remain
untouched.
"""
from dataclasses import dataclass, field

from penx_app.domain.scan_plan import ScanPlan, assert_valid_plan
from penx_app.scanners.registry import SCANNERS


@dataclass(frozen=True)
class Profile:
    id: str
    version: int
    description: str
    scanner_keys: tuple[str, ...]
    passive_only: bool
    default_timeouts: dict[str, int] = field(default_factory=dict)
    max_parallelism: int = 1
    global_budget_seconds: int | None = None


BUILTIN_PROFILES: dict[str, Profile] = {
    'passive': Profile(
        id='passive', version=1,
        description='Passive-only collection without active adapters.',
        scanner_keys=(), passive_only=True,
    ),
    'standard': Profile(
        id='standard', version=1,
        description='Standard active scan matching preset a: Nmap, WHOIS, '
                    'WhatWeb, HTTP headers, DNS.',
        scanner_keys=('1', '2', '3', '4', '5'), passive_only=False,
    ),
    'web_audit': Profile(
        id='web_audit', version=1,
        description='Controlled web/TLS audit: WhatWeb, HTTP headers, Nikto, '
                    'Nuclei, httpx, TLS (consent required).',
        scanner_keys=('3', '4', '6', '7', '8', 'd'), passive_only=False,
    ),
    'full_assessment': Profile(
        id='full_assessment', version=1,
        description='Full assessment covering every registry scanner '
                    'including endpoint mapping (consent required).',
        scanner_keys=tuple(SCANNERS), passive_only=False,
    ),
}
BUILTIN_PROFILE_ORDER = ('passive', 'standard', 'web_audit',
                         'full_assessment')

_CUSTOM_PLAN_FIELDS = ('per_scanner_timeouts', 'max_parallelism',
                       'global_budget_seconds', 'dispatch_interval_seconds')


def profile_to_plan(profile: Profile, target: str, *, active_consent: bool,
                   per_scanner_timeouts: dict[str, int] | None = None,
                   max_parallelism: int | None = None,
                   global_budget_seconds: int | None = None,
                   dispatch_interval_seconds: float | None = None) -> ScanPlan:
    """Build a ScanPlan from a profile.

    Caller-supplied overrides beat profile defaults. Consent keys still
    require `active_consent` (plan validation rule R6 applies).
    """
    timeouts = dict(profile.default_timeouts)
    if per_scanner_timeouts is not None:
        timeouts.update(per_scanner_timeouts)
    plan = ScanPlan(
        profile_id=profile.id,
        profile_version=profile.version,
        target=target,
        scanner_keys=profile.scanner_keys,
        passive_only=profile.passive_only,
        active_consent=active_consent,
        per_scanner_timeouts=timeouts,
        max_parallelism=(max_parallelism if max_parallelism is not None
                         else profile.max_parallelism),
        global_budget_seconds=(global_budget_seconds
                               if global_budget_seconds is not None
                               else profile.global_budget_seconds),
        dispatch_interval_seconds=dispatch_interval_seconds,
    )
    assert_valid_plan(plan)
    return plan


def build_custom_plan(target: str, keys: tuple[str, ...], *,
                     active_consent: bool, **overrides) -> ScanPlan:
    """Deterministic plan for an explicit user selection (profile 'custom').

    Accepted overrides: per_scanner_timeouts, max_parallelism,
    global_budget_seconds, dispatch_interval_seconds.
    """
    values = dict(zip(_CUSTOM_PLAN_FIELDS, (
        dict(overrides.get('per_scanner_timeouts') or {}),
        overrides.get('max_parallelism', 1),
        overrides.get('global_budget_seconds'),
        overrides.get('dispatch_interval_seconds'),
    )))
    unknown = set(overrides) - set(_CUSTOM_PLAN_FIELDS)
    if unknown:
        raise TypeError('Unknown plan overrides: ' + ', '.join(sorted(unknown)))
    plan = ScanPlan(
        profile_id='custom',
        profile_version=1,
        target=target,
        scanner_keys=tuple(keys),
        passive_only=False,
        active_consent=active_consent,
        **values,
    )
    assert_valid_plan(plan)
    return plan


def list_profiles() -> tuple[Profile, ...]:
    """Built-in profiles in stable order (for CLI menus and reports)."""
    return tuple(BUILTIN_PROFILES[key] for key in BUILTIN_PROFILE_ORDER)


def get_profile(profile_id: str) -> Profile:
    """Return a built-in profile; KeyError for unknown or typo'd ids."""
    try:
        return BUILTIN_PROFILES[profile_id]
    except KeyError:
        raise KeyError(f'Unknown scan profile: {profile_id!r}') from None
