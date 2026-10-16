"""Opt-in scanner cancellation tests using only synthetic local Python processes."""
from __future__ import annotations

from contextlib import redirect_stdout
from io import StringIO
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from penx_app.scanners.process_runner import run_tool


class CooperativeCancellationContracts(unittest.TestCase):
    def test_precancelled_request_does_not_start_any_process(self):
        event = threading.Event()
        event.set()
        with patch("penx_app.scanners.process_runner.subprocess.Popen",
                   side_effect=AssertionError("scanner process must never spawn")):
            result = run_tool(["fixture-scanner", "target.invalid"], cancel_event=event)
        self.assertEqual(result.status, "PARTIAL")
        self.assertFalse(result.evidence)
        self.assertIsNone(result.exit_code)
        self.assertIn("cancelled", str(result))
        self.assertNotIn("target.invalid", str(result))
        self.assertIn("cancellation", result.diagnostics)

    def exercise_running_tree(self, live: bool):
        with tempfile.TemporaryDirectory(prefix="penx-cooperative-stop-") as root:
            folder = Path(root)
            marker = folder / "spawned.txt"
            survivor = folder / "descendant-survived.txt"
            child = (
                "import os,pathlib,time;"
                "time.sleep(1.8);"
                "pathlib.Path(os.environ['PENX_TEST_SURVIVOR']).write_text('bad')"
            )
            parent = (
                "import pathlib,subprocess,sys,time;"
                "subprocess.Popen([sys.executable,'-c'," + repr(child) + "]);"
                "pathlib.Path(" + repr(str(marker)) + ").write_text('started');"
                "print('scanner started', flush=True);"
                "time.sleep(20)"
            )
            env = dict(os.environ, PENX_TEST_SURVIVOR=str(survivor))
            event = threading.Event()
            outcome = []
            exceptions = []

            def scan():
                try:
                    outcome.append(run_tool([sys.executable, "-c", parent],
                                            timeout=12, env=env,
                                            cancel_event=event))
                except BaseException as exc:
                    exceptions.append(exc)

            runner = threading.Thread(target=scan, daemon=True)
            with patch.dict(os.environ, {"PENX_LIVE_OUTPUT": "1" if live else "0"}), \
                    redirect_stdout(StringIO()):
                runner.start()
                deadline = time.monotonic() + 9
                while not marker.exists() and time.monotonic() < deadline:
                    time.sleep(0.02)
                # Always signal on a test failure so child processes get torn down.
                event.set()
                runner.join(timeout=9)

            self.assertTrue(marker.exists(), "synthetic parent did not launch")
            self.assertFalse(runner.is_alive(), "cancellation did not stop the scanner")
            self.assertEqual(exceptions, [])
            self.assertEqual(len(outcome), 1)
            self.assertEqual(outcome[0].status, "PARTIAL")
            self.assertFalse(outcome[0].evidence)
            self.assertIn("cancelled", str(outcome[0]))
            self.assertNotIn("scanner started", str(outcome[0]),
                             "cancelled partial output must not become evidence")
            time.sleep(2.0)
            self.assertFalse(survivor.exists(), "cancellation orphaned a descendant")

    def test_quiet_cancelled_tree_has_no_orphans(self):
        self.exercise_running_tree(False)

    def test_live_cancelled_tree_has_no_orphans(self):
        self.exercise_running_tree(True)

    def test_without_cancel_token_success_behavior_remains_unchanged(self):
        with patch.dict(os.environ, {"PENX_LIVE_OUTPUT": "0"}):
            result = run_tool([sys.executable, "-c", "print('fixture success')"],
                              timeout=5)
        self.assertEqual(result.status, "COMPLETE")
        self.assertTrue(result.evidence)
        self.assertEqual(result.exit_code, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
