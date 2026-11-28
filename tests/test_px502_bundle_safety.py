"""PX-502: bounded offline import safety fixtures.

The full interoperable assessment bundle (findings, evidence anchors, machine
reports, corrections, integrity manifest, redaction) is deferred -- see
``docs/ROADMAP.md``, PX-502. The only existing bounded import path is
``penx_app.application.profile_documents``. These tests lock the safety
properties any future bundle import must preserve -- integrity, duplicate
entries, oversized inputs, privacy and unsafe-path handling -- so a new import
path cannot silently relax them. No new uncontrolled import path is added.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from penx_app.application.profile_documents import (
    MAX_PROFILE_BYTES,
    ProfileDocument,
    load_profile,
)


def _base() -> dict:
    """A known-valid profile, built from the real ``to_dict`` output."""
    return ProfileDocument('dependent', 1, ('1', '2'), dependencies=(('1', '2'),)).to_dict()


class ProfileImportSafetyTests(unittest.TestCase):
    def test_valid_profile_roundtrips_through_file(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'profile.json'
            path.write_text(json.dumps(_base()))
            document = load_profile(path)
            self.assertEqual(document.profile_id, 'dependent')
            self.assertEqual(document.to_dict(), _base())

    def test_rejects_unknown_fields(self):
        # Privacy: targets, consent and secrets are forbidden; so are other
        # unknown fields.
        for extra in ('targets', 'consent', 'secrets', 'extra_field'):
            with self.subTest(extra=extra):
                data = _base()
                data[extra] = 'x'
                with self.assertRaises(ValueError):
                    ProfileDocument.from_dict(data)

    def test_rejects_missing_required_fields(self):
        for missing in ('schema_version', 'profile_id', 'profile_version',
                        'scanner_keys', 'passive_only', 'scanner_configuration',
                        'max_parallelism', 'global_budget_seconds',
                        'dispatch_interval_seconds'):
            with self.subTest(missing=missing):
                data = _base()
                data.pop(missing)
                with self.assertRaises(ValueError):
                    ProfileDocument.from_dict(data)

    def test_rejects_wrong_schema_version(self):
        data = _base()
        data['schema_version'] = 2
        with self.assertRaises(ValueError):
            ProfileDocument.from_dict(data)

    def test_rejects_invalid_field_types(self):
        cases = {
            'profile_id': 'Bad-ID',
            'profile_version': 0,
            'passive_only': 'yes',
            'max_parallelism': 0,
            'max_parallelism': 9,
            'global_budget_seconds': 10,
            'global_budget_seconds': 3601,
            'dispatch_interval_seconds': 0,
            'dispatch_interval_seconds': '5',
            'dispatch_interval_seconds': True,
        }
        for field, value in cases.items():
            with self.subTest(field=field, value=value):
                data = _base()
                data[field] = value
                with self.assertRaises(ValueError):
                    ProfileDocument.from_dict(data)

    def test_rejects_too_many_scanners(self):
        data = _base()
        data['scanner_keys'] = [str(i) for i in range(14)]
        with self.assertRaises(ValueError):
            ProfileDocument.from_dict(data)

    def test_rejects_too_many_dependencies(self):
        data = _base()
        data['dependencies'] = [[1, 2]] * 170
        with self.assertRaises(ValueError):
            ProfileDocument.from_dict(data)

    def test_passive_profile_forbids_active_configuration(self):
        data = _base()
        data['passive_only'] = True
        data['max_parallelism'] = 2
        with self.assertRaises(ValueError):
            ProfileDocument.from_dict(data)

    def test_rejects_duplicate_json_fields(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'profile.json'
            path.write_text('{"schema_version": 1, "profile_id": "a", "profile_id": "b"}')
            with self.assertRaises(ValueError):
                load_profile(path)

    def test_rejects_oversized_profile(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'profile.json'
            # 65,537 bytes: the size cap must reject before JSON parsing.
            path.write_bytes(b'a' * (MAX_PROFILE_BYTES + 1))
            with self.assertRaises(ValueError):
                load_profile(path)

    def test_rejects_missing_and_directory_paths(self):
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(FileNotFoundError):
                load_profile(Path(root) / 'nope.json')
            with self.assertRaises(OSError):
                load_profile(Path(root))

    def test_loaded_profile_excludes_targets_and_credentials(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'profile.json'
            path.write_text(json.dumps({**_base(), 'targets': ['192.0.2.1'], 'consent': 'yes'}))
            with self.assertRaises(ValueError):
                load_profile(path)


if __name__ == '__main__':
    unittest.main()
