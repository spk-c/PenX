"""Bounded structured runtime diagnostics for persisted scanner metadata.

`ScannerRunEvent` is one lifecycle transition of a scheduled adapter node
(dispatch or terminal outcome). Events are recorded by the plan executor and
serialized into `ScanResult.metadata()` as version 3. The caps mirror the
existing metadata caps (100 adapters) and keep every event row small enough
for offline storage.
"""
from __future__ import annotations

import math
from dataclasses import dataclass

EVENT_NAMES = ('started', 'completed', 'failed', 'skipped', 'cancelled')
MAX_EVENTS_PER_ADAPTER = 8
MAX_NOTE_LENGTH = 200

_EVENT_FIELDS = {'scanner_id', 'event', 'duration_seconds', 'exit_code', 'note'}


@dataclass(frozen=True)
class ScannerRunEvent:
    scanner_id: str
    event: str                  # one of EVENT_NAMES
    duration_seconds: float | None
    exit_code: int | None
    note: str                   # <= 200 chars

    def __post_init__(self):
        if not isinstance(self.scanner_id, str) or not self.scanner_id:
            raise ValueError('Invalid scanner run event identity')
        if self.event not in EVENT_NAMES:
            raise ValueError('Unknown scanner run event')
        if self.duration_seconds is not None:
            if (isinstance(self.duration_seconds, bool)
                    or not isinstance(self.duration_seconds, (int, float))
                    or not math.isfinite(self.duration_seconds)
                    or self.duration_seconds < 0):
                raise ValueError('Invalid scanner run event duration')
        if self.exit_code is not None and type(self.exit_code) is not int:
            raise ValueError('Invalid scanner run event exit code')
        if not isinstance(self.note, str) or len(self.note) > MAX_NOTE_LENGTH:
            raise ValueError('Invalid scanner run event note')

    def to_dict(self) -> dict:
        return {'scanner_id': self.scanner_id, 'event': self.event,
                'duration_seconds': self.duration_seconds,
                'exit_code': self.exit_code, 'note': self.note}

    @classmethod
    def from_dict(cls, value: dict) -> 'ScannerRunEvent':
        """Strict parse of one serialized event (metadata version 3)."""
        if not isinstance(value, dict) or set(value) != _EVENT_FIELDS:
            raise ValueError('Unexpected run event fields')
        duration = value['duration_seconds']
        if duration is not None:
            if (isinstance(duration, bool)
                    or not isinstance(duration, (int, float))
                    or not math.isfinite(duration)
                    or duration < 0):
                raise ValueError('Invalid run event duration')
            duration = float(duration)
        exit_code = value['exit_code']
        if exit_code is not None and type(exit_code) is not int:
            raise ValueError('Invalid run event exit code')
        return cls(value['scanner_id'], value['event'], duration, exit_code,
                   value['note'])


@dataclass(frozen=True)
class PlanSummary:
    """Plan identity carried in metadata version 3 (no budgets/keys)."""

    profile_id: str
    profile_version: int
    max_parallelism: int
    global_budget_seconds: int | None

    def __post_init__(self):
        if not isinstance(self.profile_id, str) or not self.profile_id:
            raise ValueError('Invalid plan profile id')
        if type(self.profile_version) is not int or self.profile_version < 1:
            raise ValueError('Invalid plan profile version')
        if type(self.max_parallelism) is not int or self.max_parallelism < 1:
            raise ValueError('Invalid plan parallelism')
        if (self.global_budget_seconds is not None
                and (type(self.global_budget_seconds) is not int
                     or self.global_budget_seconds < 1)):
            raise ValueError('Invalid plan global budget')
