"""Contract tests for the versioned ScanPlan domain type (P1-1)."""
import unittest

from penx_app.domain.scan_models import ScanRequest
from penx_app.domain.scan_plan import (
    PlanValidationError,
    ScanPlan,
    assert_valid_plan,
    validate_plan,
)
from penx_app.scanners.registry import SCANNERS

ALL_KEYS = tuple(SCANNERS)


def make_plan(**overrides) -> ScanPlan:
    base = dict(
        profile_id='standard',
        profile_version=1,
        target='example.com',
        scanner_keys=('1', '2'),
        passive_only=False,
        active_consent=False,
        per_scanner_timeouts={},
        max_parallelism=1,
        global_budget_seconds=None,
        dispatch_interval_seconds=None,
    )
    base.update(overrides)
    return ScanPlan(**base)


def errors_for(**overrides) -> list[str]:
    return validate_plan(make_plan(**overrides))


class ScanPlanContractTests(unittest.TestCase):
    def test_valid_minimal_plan(self):
        self.assertEqual(errors_for(), [])
        assert_valid_plan(make_plan())

    def test_to_request_round_trip(self):
        plan = make_plan(target='10.0.0.5', scanner_keys=('7',),
                         active_consent=True)
        request = plan.to_request()
        self.assertIsInstance(request, ScanRequest)
        self.assertEqual(request.target, '10.0.0.5')
        self.assertEqual(request.scanner_ids, ('7',))
        self.assertFalse(request.passive_only)
        self.assertTrue(request.active_consent)

    # R1
    def test_r1_profile_id_must_be_non_empty_string(self):
        self.assertTrue(any(e.startswith('R1:') for e in errors_for(profile_id='')))
        self.assertTrue(any(e.startswith('R1:') for e in errors_for(profile_id='  ')))
        self.assertTrue(any(e.startswith('R1:') for e in errors_for(profile_id=3)))

    def test_r1_profile_version_must_be_strict_int(self):
        self.assertTrue(any(e.startswith('R1:') for e in errors_for(profile_version=0)))
        self.assertTrue(any(e.startswith('R1:') for e in errors_for(profile_version=True)))
        self.assertTrue(any(e.startswith('R1:') for e in errors_for(profile_version='1')))
        self.assertEqual(errors_for(profile_version=2), [])

    # R2
    def test_r2_target_must_be_non_empty_string(self):
        self.assertTrue(any(e.startswith('R2:') for e in errors_for(target='')))
        self.assertTrue(any(e.startswith('R2:') for e in errors_for(target='   ')))
        self.assertEqual(errors_for(target='a b'), [])

    # R3
    def test_r3_keys_must_be_unique_known_registry_keys(self):
        self.assertTrue(any(e.startswith('R3:') for e in
                            errors_for(scanner_keys=('1', '1'))))
        self.assertTrue(any(e.startswith('R3:') for e in
                            errors_for(scanner_keys=('1', 'z'))))
        self.assertTrue(any(e.startswith('R3:') for e in
                            errors_for(scanner_keys=['1'])))
        self.assertEqual(errors_for(scanner_keys=('8', 'd')), [])

    # R4
    def test_r4_passive_only_plan_shape(self):
        self.assertEqual(
            errors_for(passive_only=True, scanner_keys=(),
                       active_consent=False), [])
        self.assertTrue(any(e.startswith('R4:') for e in
                            errors_for(passive_only=True, scanner_keys=('1',))))
        self.assertTrue(any(e.startswith('R4:') for e in
                            errors_for(passive_only=True, scanner_keys=(),
                                       active_consent=True)))

    # R5
    def test_r5_active_plan_needs_at_least_one_key(self):
        self.assertTrue(any(e.startswith('R5:') for e in
                            errors_for(scanner_keys=())))

    # R6
    def test_r6_consent_keys_require_active_consent(self):
        for key in ('7', '9', 'e', 'c'):
            self.assertTrue(any(e.startswith('R6:') for e in
                                errors_for(scanner_keys=(key,))), key)
            self.assertEqual(errors_for(scanner_keys=(key,),
                                        active_consent=True), [], key)
        # No consent key -> no R6 error without consent.
        self.assertEqual(errors_for(scanner_keys=('1', 'd')), [])

    # R7
    def test_r7_per_scanner_timeouts(self):
        self.assertEqual(errors_for(per_scanner_timeouts={'1': 120}), [])
        self.assertEqual(errors_for(per_scanner_timeouts={'1': 30, '2': 900}), [])
        self.assertTrue(any(e.startswith('R7:') for e in
                            errors_for(per_scanner_timeouts={'1': 29})))
        self.assertTrue(any(e.startswith('R7:') for e in
                            errors_for(per_scanner_timeouts={'1': 901})))
        self.assertTrue(any(e.startswith('R7:') for e in
                            errors_for(per_scanner_timeouts={'3': 100})))
        self.assertTrue(any(e.startswith('R7:') for e in
                            errors_for(per_scanner_timeouts={'1': True})))
        self.assertTrue(any(e.startswith('R7:') for e in
                            errors_for(per_scanner_timeouts={'1': '120'})))

    # R8
    def test_r8_max_parallelism_must_be_strict_int(self):
        self.assertTrue(any(e.startswith('R8:') for e in
                            errors_for(max_parallelism=0)))
        self.assertTrue(any(e.startswith('R8:') for e in
                            errors_for(max_parallelism=True)))
        self.assertTrue(any(e.startswith('R8:') for e in
                            errors_for(max_parallelism=1.0)))
        self.assertTrue(any(e.startswith('R8:') for e in
                            errors_for(max_parallelism=-2)))
        self.assertEqual(errors_for(max_parallelism=4), [])

    # R9
    def test_r9_global_budget(self):
        self.assertEqual(errors_for(global_budget_seconds=30), [])
        self.assertTrue(any(e.startswith('R9:') for e in
                            errors_for(global_budget_seconds=29)))
        self.assertTrue(any(e.startswith('R9:') for e in
                            errors_for(global_budget_seconds=True)))
        self.assertTrue(any(e.startswith('R9:') for e in
                            errors_for(global_budget_seconds='30')))

    # R10
    def test_r10_dispatch_interval(self):
        self.assertEqual(errors_for(dispatch_interval_seconds=0.5), [])
        self.assertTrue(any(e.startswith('R10:') for e in
                            errors_for(dispatch_interval_seconds=0)))
        self.assertTrue(any(e.startswith('R10:') for e in
                            errors_for(dispatch_interval_seconds=-1)))
        self.assertTrue(any(e.startswith('R10:') for e in
                            errors_for(dispatch_interval_seconds=61)))
        self.assertTrue(any(e.startswith('R10:') for e in
                            errors_for(dispatch_interval_seconds=True)))
        self.assertTrue(any(e.startswith('R10:') for e in
                            errors_for(dispatch_interval_seconds=float('inf'))))

    def test_all_violations_reported_at_once(self):
        errors = errors_for(
            target='',
            scanner_keys=('1', '1', 'z'),
            active_consent=False,
            per_scanner_timeouts={'2': 29},
            max_parallelism=0,
            global_budget_seconds=10,
            dispatch_interval_seconds=0,
        )
        for rule in ('R2', 'R3', 'R7', 'R8', 'R9', 'R10'):
            self.assertTrue(any(e.startswith(rule + ':') for e in errors),
                            (rule, errors))

    def test_full_registry_plan_requires_consent(self):
        self.assertEqual(
            errors_for(scanner_keys=ALL_KEYS, active_consent=True), [])
        self.assertTrue(any(e.startswith('R6:') for e in
                            errors_for(scanner_keys=ALL_KEYS)))

    def test_assert_valid_plan_raises_with_all_violations(self):
        with self.assertRaises(PlanValidationError) as caught:
            assert_valid_plan(make_plan(max_parallelism=0,
                                        global_budget_seconds=10))
        self.assertIn('R8', str(caught.exception))
        self.assertIn('R9', str(caught.exception))
        self.assertIsInstance(caught.exception, ValueError)


if __name__ == '__main__':
    unittest.main()
