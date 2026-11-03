"""PX-002: all scanner registry IDs retain errors from both scheduler reapers.

Only synthetic worker failures; never executes a scanner or performs I/O.
"""
from __future__ import annotations

import time
import unittest
from unittest.mock import patch

from penx_app.application.headless_scan import scan_report
from penx_app.application.scan_planner import run_plan
from penx_app.application.scan_profiles import build_custom_plan
from penx_app.domain.scan_models import ScanResult
from penx_app.reporting.machine_reports import sarif_from_report
from penx_app.scanners.registry import SCANNERS


def failing_worker(*_args, **_kwargs):
    # An incomplete future must reach the post-wait reaper, not the initial
    # future.done() fast path, or this regression would be missed.
    time.sleep(0.025)
    raise RuntimeError("simulated\nadapter exception")


def force_wait(futures, *args, **kwargs):
    # Deterministic synthetic scheduler. Futures may be incomplete, but
    # future.result() will wait and raise after worker exits.
    return set(futures), set()


class Px002SchedulerReasonMatrixTests(unittest.TestCase):
    def test_exception_from_post_wait_reaper_keeps_code_in_all_outputs(self):
        self.assertGreaterEqual(len(SCANNERS), 12)
        for key, spec in SCANNERS.items():
            with self.subTest(scanner=spec.id):
                plan = build_custom_plan(
                    "example.test", (key,), active_consent=True,
                    max_parallelism=2, global_budget_seconds=60)
                menu = {key: (spec.id, lambda _target: None)}
                with patch(
                    "penx_app.application.scan_planner._run_adapter",
                    side_effect=failing_worker,
                ) as execution, patch(
                    "penx_app.application.scan_planner.concurrent.futures.wait",
                    side_effect=force_wait,
                ) as waiter:
                    result = run_plan(plan, menu=menu)
                execution.assert_called_once()
                waiter.assert_called()
                self.assertEqual(len(result.results), 1)
                row=result.results[0]
                self.assertEqual(row.scanner_id, spec.id)
                self.assertEqual(row.status, "FAILED")
                self.assertFalse(row.evidence)
                self.assertEqual(row.reason, "error")
                self.assertEqual(row.run_events[-1].event, "failed")
                self.assertNotIn("\n", row.diagnostics)
                self.assertNotIn("\n", row.text)
                restored=ScanResult.from_metadata(result.metadata())
                self.assertEqual(restored.results[0].reason, "error")
                report=scan_report(plan, result)
                self.assertEqual(report["adapters"][0]["reason"], "error")
                self.assertEqual(report["findings"], [])
                sarif=sarif_from_report(report)
                notifications=sarif["runs"][0]["invocations"][0][
                    "toolExecutionNotifications"]
                self.assertEqual(len(notifications), 1)
                self.assertEqual(notifications[0]["properties"]["reason"],
                                 "error")


if __name__=="__main__":
    unittest.main()
