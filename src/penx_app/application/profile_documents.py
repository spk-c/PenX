"""Bounded versioned profile import/export, excluding targets and credentials."""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import math
from pathlib import Path
import re

from penx_app.application.scan_profiles import get_profile
from penx_app.domain.scan_plan import ScanPlan, assert_valid_plan
from penx_app.domain.scanner_configuration import ScannerConfiguration
from penx_app.file_output import publish_unique

MAX_PROFILE_BYTES = 65_536


@dataclass(frozen=True)
class ProfileDocument:
    profile_id: str
    profile_version: int
    scanner_keys: tuple[str, ...]
    passive_only: bool = False
    scanner_configuration: tuple[ScannerConfiguration, ...] = ()
    max_parallelism: int = 1
    global_budget_seconds: int | None = None
    dispatch_interval_seconds: float | None = None

    def __post_init__(self):
        if (not isinstance(self.scanner_configuration, tuple) or len(self.scanner_configuration) > 13
                or any(not isinstance(item, ScannerConfiguration) for item in self.scanner_configuration)):
            raise ValueError('Invalid profile scanner configuration')
        if not isinstance(self.profile_id, str) or not re.fullmatch(r'[a-z][a-z0-9_-]{0,63}', self.profile_id):
            raise ValueError('Profile ID must be a bounded lowercase identifier')
        if type(self.profile_version) is not int or self.profile_version < 1:
            raise ValueError('Profile version must be a positive integer')
        if type(self.passive_only) is not bool:
            raise ValueError('passive_only must be a boolean')
        if type(self.max_parallelism) is not int or not 1 <= self.max_parallelism <= 8:
            raise ValueError('Profile parallelism must be an integer in 1..8')
        if self.global_budget_seconds is not None and (
                type(self.global_budget_seconds) is not int or not 30 <= self.global_budget_seconds <= 3600):
            raise ValueError('Profile global budget must be an integer in 30..3600')
        interval = self.dispatch_interval_seconds
        if interval is not None and (isinstance(interval, bool) or not isinstance(interval, (int, float))
                                     or not math.isfinite(interval) or not 0 < interval <= 60):
            raise ValueError('Invalid profile dispatch interval')
        if self.passive_only and (self.max_parallelism != 1 or self.global_budget_seconds is not None
                                  or interval is not None or self.scanner_configuration):
            raise ValueError('Passive provider planner settings are unsupported')
        # Structural validation uses a placeholder scope, never a stored target.
        self.to_plan('profile-validation.invalid', active_consent=not self.passive_only)

    def to_plan(self, target: str, *, active_consent: bool) -> ScanPlan:
        plan = ScanPlan(
            self.profile_id, self.profile_version, target, self.scanner_keys,
            self.passive_only, active_consent,
            {item.scanner_key: item.timeout_seconds for item in self.scanner_configuration
             if item.timeout_seconds is not None},
            self.max_parallelism, self.global_budget_seconds, self.dispatch_interval_seconds,
            scanner_configuration=self.scanner_configuration)
        assert_valid_plan(plan)
        return plan

    def to_dict(self) -> dict:
        return {
            'schema_version': 1, 'profile_id': self.profile_id,
            'profile_version': self.profile_version, 'scanner_keys': list(self.scanner_keys),
            'passive_only': self.passive_only,
            'scanner_configuration': [item.to_dict() for item in self.scanner_configuration],
            'max_parallelism': self.max_parallelism,
            'global_budget_seconds': self.global_budget_seconds,
            'dispatch_interval_seconds': self.dispatch_interval_seconds,
        }

    @classmethod
    def from_dict(cls, value: dict) -> ProfileDocument:
        fields = {'schema_version', 'profile_id', 'profile_version', 'scanner_keys',
                  'passive_only', 'scanner_configuration', 'max_parallelism',
                  'global_budget_seconds', 'dispatch_interval_seconds'}
        if not isinstance(value, dict) or set(value) != fields:
            raise ValueError('Missing or unknown profile fields; targets, consent and secrets are forbidden')
        if type(value['schema_version']) is not int or value['schema_version'] != 1:
            raise ValueError('Unsupported profile schema version')
        if not isinstance(value['scanner_keys'], list) or not isinstance(value['scanner_configuration'], list):
            raise ValueError('Profile scanners and configuration must be arrays')
        if len(value['scanner_keys']) > 13 or len(value['scanner_configuration']) > 13:
            raise ValueError('Too many configured scanners')
        data = {key: item for key, item in value.items() if key != 'schema_version'}
        data['scanner_keys'] = tuple(data['scanner_keys'])
        data['scanner_configuration'] = tuple(ScannerConfiguration.from_dict(item)
                                               for item in data['scanner_configuration'])
        return cls(**data)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON profile field')
        result[key] = value
    return result


def load_profile(path: str | Path) -> ProfileDocument:
    with Path(path).open('rb') as handle:
        content = handle.read(MAX_PROFILE_BYTES + 1)
    if len(content) > MAX_PROFILE_BYTES:
        raise ValueError('Profile exceeds 64 KiB')
    return ProfileDocument.from_dict(json.loads(content.decode('utf-8'), object_pairs_hook=_unique_object))


def builtin_document(profile_id: str) -> ProfileDocument:
    profile = get_profile(profile_id)
    return ProfileDocument(profile.id, profile.version, profile.scanner_keys,
                           profile.passive_only,
                           tuple(ScannerConfiguration(key, timeout_seconds=value)
                                 for key, value in profile.default_timeouts.items()),
                           profile.max_parallelism, profile.global_budget_seconds)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog='penx profiles')
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument('--validate', metavar='FILE')
    action.add_argument('--export', metavar='BUILTIN_ID')
    action.add_argument('--copy', metavar='FILE', help='Validate and canonically export a custom profile')
    parser.add_argument('--output', default='.')
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    try:
        if args.validate:
            document = load_profile(args.validate)
            print(f'Valid profile: {document.profile_id} v{document.profile_version}; no scanners started.')
        else:
            document = load_profile(args.copy) if args.copy else builtin_document(args.export)
            path = publish_unique(args.output, document.profile_id, '.profile.json',
                                  json.dumps(document.to_dict(), indent=2) + '\n')
            print('Profile: ' + str(path))
        return 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print('[!] Profile: ' + str(exc))
        return 2
