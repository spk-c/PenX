"""P1-2: plan executor behavior with mock adapters (offline, no subprocesses)."""
import threading
import time
import unittest
from unittest import mock

from penx_app.application.scan_planner import run_plan
from penx_app.domain.scan_plan import PlanValidationError, ScanPlan


def make_plan(keys, *, parallelism=1, **overrides) -> ScanPlan:
    base = dict(
        profile_id='executor', profile_version=1, target='example.com',
        scanner_keys=tuple(keys), passive_only=False, active_consent=True,
        per_scanner_timeouts={}, max_parallelism=parallelism,
        global_budget_seconds=None, dispatch_interval_seconds=None)
    base.update(overrides)
    return ScanPlan(**base)


def make_adapter(calls, text='[OK] fixture output', sleep=0.0, exc=None):
    def run(target):
        calls.append(target)
        if sleep:
            time.sleep(sleep)
        if exc is not None:
            raise exc
        return text

    return run


def row_map(result):
    return {row.scanner_id: row for row in result.results}


def snapshot(result):
    return [(row.scanner_id, row.status, row.text, row.evidence)
            for row in result.results]


class PlanExecutorDeterminismTests(unittest.TestCase):
    def test_sequential_delegation_is_deterministic(self):
        menu = {'1': ('Nmap', make_adapter([])),
                '2': ('Whois', make_adapter([]))}
        plan = make_plan(('1', '2'))
        first = run_plan(plan, menu=menu)
        second = run_plan(plan, menu=menu)
        self.assertEqual(snapshot(first), snapshot(second))
        self.assertEqual([row.scanner_id for row in first.results],
                         ['nmap', 'whois'])

    def test_parallel_rows_always_follow_plan_order(self):
        def menu_for():
            return {
                '1': ('Nmap', make_adapter([], text='[OK] nmap')),
                '2': ('Whois', make_adapter([], text='[OK] whois')),
                '3': ('Web fingerprint', make_adapter([], text='[OK] whatweb')),
                '4': ('HTTP headers', make_adapter([], text='[OK] headers')),
            }
        plan = make_plan(('1', '2', '3', '4'), parallelism=2)
        for _ in range(3):
            result = run_plan(plan, menu=menu_for())
            self.assertEqual(
                [row.scanner_id for row in result.results],
                ['nmap', 'whois', 'whatweb', 'http_headers'])
            self.assertEqual(
                [row.text for row in result.results],
                ['[OK] nmap', '[OK] whois', '[OK] whatweb', '[OK] headers'])


class PlanExecutorConcurrencyTests(unittest.TestCase):
    def test_parallel_adapters_overlap_in_time(self):
        calls = {'1': [], '2': []}
        menu = {'1': ('Nmap', make_adapter(calls['1'], sleep=0.4)),
                '2': ('Whois', make_adapter(calls['2'], sleep=0.4))}
        started = time.monotonic()
        result = run_plan(make_plan(('1', '2'), parallelism=2), menu=menu)
        elapsed = time.monotonic() - started
        self.assertEqual([row.status for row in result.results],
                         ['COMPLETE', 'COMPLETE'])
        # Sequential would need >= 0.8 s; overlapping workers must beat that.
        self.assertLess(elapsed, 0.75)

    def test_error_isolation_in_parallel_path(self):
        menu = {
            '1': ('Nmap', make_adapter([], exc=RuntimeError('boom' + 'x' * 300))),
            '2': ('Whois', make_adapter([], text='[OK] whois')),
        }
        result = run_plan(make_plan(('1', '2'), parallelism=2), menu=menu)
        rows = row_map(result)
        self.assertEqual(rows['nmap'].status, 'FAILED')
        self.assertIn('RuntimeError', rows['nmap'].text)
        self.assertLessEqual(len(rows['nmap'].diagnostics), 220)
        self.assertEqual(rows['whois'].status, 'COMPLETE')

    def test_cancel_before_start_marks_every_row_partial(self):
        for parallelism in (1, 2):
            with self.subTest(parallelism=parallelism):
                calls = []
                menu = {'1': ('Nmap', make_adapter(calls)),
                        '2': ('Whois', make_adapter(calls))}
                cancel = threading.Event()
                cancel.set()
                result = run_plan(
                    make_plan(('1', '2'), parallelism=parallelism),
                    menu=menu, cancel_event=cancel)
                self.assertEqual(calls, [])
                for row in result.results:
                    self.assertEqual(row.status, 'PARTIAL')
                    self.assertEqual(
                        row.diagnostics,
                        'Not started: caller cancelled scan sequence')

    def test_cancel_mid_run_pending_rows_are_partial(self):
        menu = {
            '1': ('Nmap', make_adapter([], sleep=0.5)),
            '2': ('Whois', make_adapter([], sleep=0.5)),
            '5': ('DNS', make_adapter([], sleep=0.5)),
        }
        cancel = threading.Event()

        def fire_later():
            time.sleep(0.1)
            cancel.set()

        timer = threading.Thread(target=fire_later, daemon=True)
        timer.start()
        result = run_plan(make_plan(('1', '2', '5'), parallelism=2),
                          menu=menu, cancel_event=cancel)
        timer.join(timeout=5)
        rows = row_map(result)
        self.assertEqual(rows['nmap'].status, 'COMPLETE')
        self.assertEqual(rows['whois'].status, 'COMPLETE')
        self.assertEqual(rows['dns'].status, 'PARTIAL')
        self.assertEqual(
            rows['dns'].diagnostics,
            'Not started: caller cancelled scan sequence')

    def test_508_overload_skips_sensitive_node_in_parallel_path(self):
        sensitive_calls = []
        menu = {
            '1': ('Nmap', make_adapter([],
                                       text='HTTP 508 Resource Limit '
                                            'Is Reached\nnginx')),
            '5': ('DNS', make_adapter([], text='[OK] dns')),
            '6': ('Nikto', make_adapter(sensitive_calls, sleep=0.1)),
        }
        result = run_plan(make_plan(('1', '5', '6'), parallelism=2),
                          menu=menu)
        rows = row_map(result)
        self.assertEqual(rows['nmap'].status, 'COMPLETE')
        self.assertEqual(rows['dns'].status, 'COMPLETE')
        self.assertEqual(rows['nikto'].status, 'PARTIAL')
        self.assertEqual(
            rows['nikto'].diagnostics,
            'Skipped after HTTP 508 from a previous selected scanner')
        self.assertEqual(sensitive_calls, [])

    def test_budget_exhaustion_marks_pending_rows_partial(self):
        # The first adapter must consume the whole budget so the pending
        # node is past the deadline when it would be dispatched.
        with mock.patch('penx_app.domain.scan_plan.'
                        'MIN_GLOBAL_BUDGET_SECONDS', 1):
            menu = {'1': ('Nmap', make_adapter([], sleep=2.2)),
                    '2': ('Whois', make_adapter([]))}
            plan = make_plan(('1', '2'), parallelism=1,
                             global_budget_seconds=2)
            result = run_plan(plan, menu=menu)
            rows = row_map(result)
            self.assertEqual(rows['nmap'].status, 'COMPLETE')
            self.assertEqual(rows['whois'].status, 'PARTIAL')
            self.assertEqual(
                rows['whois'].diagnostics,
                'Not started: global budget exhausted')

    def test_dispatch_interval_limits_start_rate(self):
        starts = []

        def timed(text):
            def run(target):
                starts.append(time.monotonic())
                return text

            return run

        menu = {'1': ('Nmap', timed('[OK] a')),
                '2': ('Whois', timed('[OK] b')),
                '3': ('DNS', timed('[OK] c'))}
        plan = make_plan(('1', '2', '3'), parallelism=3,
                         dispatch_interval_seconds=0.5)
        result = run_plan(plan, menu=menu)
        self.assertEqual([row.status for row in result.results],
                         ['COMPLETE', 'COMPLETE', 'COMPLETE'])
        self.assertEqual(len(starts), 3)
        for first, second in zip(starts, starts[1:]):
            self.assertGreaterEqual(second - first, 0.45)


class PlanExecutorGateTests(unittest.TestCase):
    def test_consent_gate_rejects_before_dispatch(self):
        calls = []
        menu = {'7': ('Nuclei', make_adapter(calls))}
        with self.assertRaises(PlanValidationError):
            run_plan(make_plan(('7',), parallelism=2,
                               active_consent=False), menu=menu)
        self.assertEqual(calls, [])

    def test_passive_plan_rejects_before_dispatch(self):
        calls = []
        menu = {'1': ('Nmap', make_adapter(calls))}
        # A *valid* passive plan (no keys, no consent) reaches the passive
        # guard; R4-invalid passive plans fail validation first.
        with self.assertRaisesRegex(ValueError, 'Passive'):
            run_plan(make_plan((), passive_only=True,
                               active_consent=False), menu=menu)
        self.assertEqual(calls, [])

    def test_invalid_passive_plan_fails_validation_first(self):
        calls = []
        menu = {'1': ('Nmap', make_adapter(calls))}
        with self.assertRaises(PlanValidationError):
            run_plan(make_plan(('1',), passive_only=True), menu=menu)
        self.assertEqual(calls, [])

    def test_unknown_plan_key_rejects_before_dispatch(self):
        calls = []
        menu = {'z': ('Unknown', make_adapter(calls))}
        with self.assertRaises(PlanValidationError):
            run_plan(make_plan(('z',), parallelism=2), menu=menu)
        self.assertEqual(calls, [])

    def test_menu_gap_rejects_before_dispatch(self):
        calls = []
        menu = {'1': ('Nmap', make_adapter(calls))}
        with self.assertRaisesRegex(ValueError, 'Invalid scanner selection'):
            run_plan(make_plan(('1', '2'), parallelism=2), menu=menu)
        self.assertEqual(calls, [])

    def test_evidence_rows_carry_bounded_anchors(self):
        menu = {'1': ('Nmap', make_adapter([], text='[OK] nmap fixture'))}
        result = run_plan(make_plan(('1',), parallelism=2), menu=menu)
        row = result.results[0]
        self.assertEqual(len(row.evidence_records), 1)
        record = row.evidence_records[0]
        self.assertEqual(record.kind, 'adapter_output')
        self.assertEqual(record.raw_start, 0)
        self.assertLessEqual(record.raw_end, len(row.text))


if __name__ == '__main__':
    unittest.main()
