"""P1-2: schedule building and per-node timeout resolution (offline)."""
import contextlib
import os
import unittest

from penx_app.application.scan_planner import (
    build_schedule,
    plan_nodes,
    resolve_node_timeout,
)
from penx_app.domain.scan_plan import PlanValidationError, ScanPlan
from penx_app.scanners.registry import SCANNERS


def make_plan(**overrides) -> ScanPlan:
    base = dict(
        profile_id='standard', profile_version=1, target='example.com',
        scanner_keys=('1', '2'), passive_only=False, active_consent=False,
        per_scanner_timeouts={}, max_parallelism=1,
        global_budget_seconds=None, dispatch_interval_seconds=None)
    base.update(overrides)
    return ScanPlan(**base)


@contextlib.contextmanager
def nmap_env_timeout(value):
    """Set/restore PENX_NMAP_TIMEOUT for one subtest."""
    key = 'PENX_NMAP_TIMEOUT'
    old = os.environ.get(key)
    if value is None:
        os.environ.pop(key, None)
    else:
        os.environ[key] = value
    try:
        yield
    finally:
        if old is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = old


class BuildScheduleTests(unittest.TestCase):
    def test_registry_order_filtered_by_plan_keys(self):
        plan = make_plan(scanner_keys=('d', '1', 's', 'c'),
                         active_consent=True)
        self.assertEqual(build_schedule(plan), ('1', 's', 'c', 'd'))

    def test_schedule_covers_full_registry_stably(self):
        plan = make_plan(scanner_keys=tuple(SCANNERS), active_consent=True)
        schedule = build_schedule(plan)
        self.assertEqual(schedule, tuple(SCANNERS))
        self.assertEqual(len(set(schedule)), len(schedule))

    def test_passive_plan_schedules_nothing(self):
        plan = make_plan(scanner_keys=(), passive_only=True)
        self.assertEqual(build_schedule(plan), ())

    def test_invalid_plan_raises_before_scheduling(self):
        with self.assertRaises(PlanValidationError):
            build_schedule(make_plan(scanner_keys=('z',)))

    def test_plan_nodes_carry_position_and_timeouts(self):
        plan = make_plan(scanner_keys=('1', '2'),
                         per_scanner_timeouts={'1': 120})
        nodes = plan_nodes(plan)
        self.assertEqual([node.key for node in nodes], ['1', '2'])
        self.assertEqual([node.position for node in nodes], [0, 1])
        self.assertEqual(nodes[0].timeout_seconds, 120)
        self.assertEqual(nodes[1].timeout_seconds, 120)


class ResolveNodeTimeoutTests(unittest.TestCase):
    def test_plan_override_beats_env_and_default(self):
        plan = make_plan(per_scanner_timeouts={'1': 120})
        with nmap_env_timeout('500'):
            self.assertEqual(resolve_node_timeout(plan, '1'), 120)

    def test_env_beats_default_with_clamp(self):
        plan = make_plan()
        cases = (('500', 500), ('5', 30), ('1000', 900), ('abc', 180),
                 (' 42 ', 42), ('', 180))
        for raw, expected in cases:
            with self.subTest(raw=raw):
                with nmap_env_timeout(raw or None):
                    self.assertEqual(
                        resolve_node_timeout(plan, '1'), expected)

    def test_default_without_env_or_override(self):
        plan = make_plan()
        with nmap_env_timeout(None):
            self.assertEqual(resolve_node_timeout(plan, '1'), 180)
            self.assertEqual(resolve_node_timeout(plan, '2'), 120)


if __name__ == '__main__':
    unittest.main()
