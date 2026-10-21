"""Versioned scan plan contract for profile-driven scan execution.

Domain-pure: no CLI, storage, network, or subprocess dependencies. The plan
carries budgets, consent, and parallelism as first-class fields so the
executor can validate everything before any adapter starts.
"""
from __future__ import annotations

import math
from dataclasses import dataclass

from penx_app.domain.scan_models import ScanRequest
from penx_app.scanners.registry import CONSENT_KEYS, SCANNERS

TIMEOUT_MIN_SECONDS = 30
TIMEOUT_MAX_SECONDS = 900
MIN_GLOBAL_BUDGET_SECONDS = 30
MAX_DISPATCH_INTERVAL_SECONDS = 60


class PlanValidationError(ValueError):
    """A scan plan violates one or more structural validation rules."""


@dataclass(frozen=True)
class ScanPlan:
    profile_id: str
    profile_version: int
    target: str
    scanner_keys: tuple[str, ...]
    passive_only: bool
    active_consent: bool
    per_scanner_timeouts: dict[str, int]
    max_parallelism: int
    global_budget_seconds: int | None
    dispatch_interval_seconds: float | None

    def to_request(self) -> ScanRequest:
        """1:1 mapping to the existing ScanRequest contract.

        Budgets and parallelism live only on the plan; the executor consumes
        the plan, not the request.
        """
        return ScanRequest(
            target=self.target,
            scanner_ids=tuple(self.scanner_keys),
            passive_only=self.passive_only,
            active_consent=self.active_consent,
        )


def _is_strict_int(value: object) -> bool:
    return type(value) is int


def validate_plan(plan: ScanPlan) -> list[str]:
    """Return every structural violation (empty list means the plan is valid)."""
    errors: list[str] = []
    # R1
    if not isinstance(plan.profile_id, str) or not plan.profile_id.strip():
        errors.append('R1: profile_id must be a non-empty string')
    if not _is_strict_int(plan.profile_version) or plan.profile_version < 1:
        errors.append('R1: profile_version must be a strict integer >= 1')
    # R2
    if not isinstance(plan.target, str) or not plan.target.strip():
        errors.append('R2: target must be a non-empty string')
    # R3
    keys = plan.scanner_keys
    if not isinstance(keys, tuple) or any(not isinstance(key, str) for key in keys):
        errors.append('R3: scanner_keys must be a tuple of registry keys')
        keys = ()
    else:
        keys = tuple(keys)
        if len(set(keys)) != len(keys):
            errors.append('R3: scanner_keys must be unique')
        unknown = [key for key in keys if key not in SCANNERS]
        if unknown:
            errors.append('R3: unknown scanner keys: ' + ', '.join(unknown))
    # R4
    if plan.passive_only:
        if keys != ():
            errors.append('R4: passive-only plans cannot schedule active scanners')
        if plan.active_consent:
            errors.append('R4: passive-only plans require active_consent to be False')
    # R5
    if not plan.passive_only and keys == ():
        errors.append('R5: active plans must schedule at least one scanner')
    # R6
    if keys and CONSENT_KEYS.intersection(keys) and not plan.active_consent:
        errors.append('R6: consent-required scanners need active_consent=True')
    # R7
    timeouts = plan.per_scanner_timeouts
    if not isinstance(timeouts, dict):
        errors.append('R7: per_scanner_timeouts must be a dict')
    else:
        for key, seconds in timeouts.items():
            if key not in keys:
                errors.append(f'R7: timeout for unscheduled scanner key {key!r}')
            elif (not _is_strict_int(seconds)
                    or not TIMEOUT_MIN_SECONDS <= seconds <= TIMEOUT_MAX_SECONDS):
                errors.append(
                    f'R7: timeout for {key!r} must be an integer between '
                    f'{TIMEOUT_MIN_SECONDS} and {TIMEOUT_MAX_SECONDS} seconds')
    # R8
    if not _is_strict_int(plan.max_parallelism) or plan.max_parallelism < 1:
        errors.append('R8: max_parallelism must be a strict integer >= 1')
    # R9
    budget = plan.global_budget_seconds
    if budget is not None and (not _is_strict_int(budget)
                               or budget < MIN_GLOBAL_BUDGET_SECONDS):
        errors.append('R9: global_budget_seconds must be None or an integer >= 30')
    # R10
    interval = plan.dispatch_interval_seconds
    if interval is not None:
        valid = (isinstance(interval, (int, float))
                 and not isinstance(interval, bool)
                 and math.isfinite(interval)
                 and 0 < interval <= MAX_DISPATCH_INTERVAL_SECONDS)
        if not valid:
            errors.append('R10: dispatch_interval_seconds must be a finite '
                          f'number > 0 and <= {MAX_DISPATCH_INTERVAL_SECONDS}')
    return errors


def assert_valid_plan(plan: ScanPlan) -> None:
    """Raise PlanValidationError listing every violation of the plan."""
    errors = validate_plan(plan)
    if errors:
        raise PlanValidationError('; '.join(errors))
