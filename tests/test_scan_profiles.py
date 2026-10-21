"""P1-3: profile registry v1 and deterministic plan builder (offline)."""
import unittest

from penx_app.application.scan_profiles import (
    BUILTIN_PROFILES,
    Profile,
    build_custom_plan,
    get_profile,
    list_profiles,
    profile_to_plan,
)
from penx_app.application.scanner_selection import (
    resolve_scanner_selection,
)
from penx_app.domain.scan_plan import PlanValidationError, validate_plan
from penx_app.scanners.registry import CONSENT_KEYS, SCANNERS


class PresetCompatibilityTests(unittest.TestCase):
    def test_standard_matches_preset_a(self):
        menu_keys = tuple(SCANNERS)
        expected = resolve_scanner_selection('a', menu_keys)
        self.assertIsInstance(expected, tuple)
        self.assertEqual(BUILTIN_PROFILES['standard'].scanner_keys, expected)

    def test_web_audit_keys_are_registry_subset_with_consent(self):
        keys = BUILTIN_PROFILES['web_audit'].scanner_keys
        self.assertTrue(set(keys) <= set(SCANNERS))
        self.assertEqual(len(keys), len(set(keys)))
        self.assertIn('7', keys)
        self.assertTrue(set(keys) & CONSENT_KEYS)

    def test_full_assessment_covers_all_registry_keys(self):
        self.assertEqual(
            BUILTIN_PROFILES['full_assessment'].scanner_keys, tuple(SCANNERS))

    def test_passive_profile_has_no_active_keys(self):
        profile = BUILTIN_PROFILES['passive']
        self.assertEqual(profile.scanner_keys, ())
        self.assertTrue(profile.passive_only)


class ProfileToPlanTests(unittest.TestCase):
    def test_all_builtins_produce_valid_plans(self):
        for profile in BUILTIN_PROFILES.values():
            with self.subTest(profile=profile.id):
                consent = not profile.passive_only
                plan = profile_to_plan(profile, 'example.com',
                                       active_consent=consent)
                self.assertEqual(validate_plan(plan), [])

    def test_caller_overrides_beat_profile_values(self):
        profile = Profile(
            id='test', version=1, description='test',
            scanner_keys=('1',), passive_only=False,
            default_timeouts={'1': 900}, max_parallelism=4,
            global_budget_seconds=60)
        plan = profile_to_plan(profile, 'example.com', active_consent=False,
                               per_scanner_timeouts={'1': 120},
                               max_parallelism=2,
                               global_budget_seconds=120)
        self.assertEqual(plan.per_scanner_timeouts, {'1': 120})
        self.assertEqual(plan.max_parallelism, 2)
        self.assertEqual(plan.global_budget_seconds, 120)
        self.assertEqual(plan.profile_id, 'test')
        self.assertEqual(plan.profile_version, 1)
        self.assertEqual(validate_plan(plan), [])

    def test_profile_values_used_when_no_overrides(self):
        profile = Profile(
            id='test', version=1, description='test',
            scanner_keys=('1',), passive_only=False,
            default_timeouts={'1': 300}, max_parallelism=3)
        plan = profile_to_plan(profile, 'example.com', active_consent=False)
        self.assertEqual(plan.per_scanner_timeouts, {'1': 300})
        self.assertEqual(plan.max_parallelism, 3)
        self.assertIsNone(plan.global_budget_seconds)

    def test_web_audit_without_consent_raises_r6(self):
        with self.assertRaises(PlanValidationError):
            profile_to_plan(BUILTIN_PROFILES['web_audit'], 'example.com',
                            active_consent=False)

    def test_web_audit_with_consent_is_valid(self):
        plan = profile_to_plan(BUILTIN_PROFILES['web_audit'], 'example.com',
                               active_consent=True)
        self.assertEqual(validate_plan(plan), [])

    def test_passive_plan_fields(self):
        plan = profile_to_plan(BUILTIN_PROFILES['passive'], 'example.com',
                               active_consent=False)
        self.assertEqual(plan.scanner_keys, ())
        self.assertTrue(plan.passive_only)
        self.assertFalse(plan.active_consent)


class ProfileRegistryApiTests(unittest.TestCase):
    def test_list_profiles_stable_order(self):
        profiles = list_profiles()
        self.assertEqual(
            [profile.id for profile in profiles],
            ['passive', 'standard', 'web_audit', 'full_assessment'])
        self.assertEqual(len(profiles), len(BUILTIN_PROFILES))

    def test_get_profile_roundtrip(self):
        for profile in BUILTIN_PROFILES.values():
            with self.subTest(profile=profile.id):
                self.assertIs(get_profile(profile.id), profile)

    def test_get_unknown_profile_raises(self):
        with self.assertRaises(KeyError):
            get_profile('nope')

    def test_custom_plan_validates_and_is_deterministic(self):
        plan = build_custom_plan('example.com', ('1', 'd'),
                                 active_consent=False)
        self.assertEqual(plan.profile_id, 'custom')
        self.assertEqual(plan.profile_version, 1)
        self.assertEqual(plan.scanner_keys, ('1', 'd'))
        self.assertEqual(validate_plan(plan), [])
        again = build_custom_plan('example.com', ('1', 'd'),
                                  active_consent=False)
        self.assertEqual(plan, again)

    def test_custom_plan_requires_consent_for_consent_keys(self):
        with self.assertRaises(PlanValidationError):
            build_custom_plan('example.com', ('7',), active_consent=False)

    def test_custom_plan_rejects_unknown_overrides(self):
        with self.assertRaises(TypeError):
            build_custom_plan('example.com', ('1',), active_consent=False,
                              nonsense=1)


if __name__ == '__main__':
    unittest.main()
