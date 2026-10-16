"""Live scanner EOF must not be mistaken for process completion.

A child can close its output handles while staying alive. It must still honor
its timeout and cancellation contract, without exposing partial text as evidence.
"""
from __future__ import annotations

from contextlib import redirect_stdout
from io import StringIO
import os
import sys
import unittest
from unittest.mock import patch

from penx_app.scanners.process_runner import run_tool


def _early_eof_command(seconds: float) -> list[str]:
    script = (
        "import os,sys,time;"
        "print('unverified partial',flush=True);"
        "os.close(1);os.close(2);"
        f"time.sleep({seconds})"
    )
    return [sys.executable, "-c", script]


class LiveScannerEarlyEofContracts(unittest.TestCase):
    def test_early_eof_running_child_times_out_as_partial(self):
        output = StringIO()
        with patch.dict(os.environ, {"PENX_LIVE_OUTPUT": "1"}), redirect_stdout(output):
            result = run_tool(_early_eof_command(4), timeout=1)
        self.assertEqual(result.status, "PARTIAL")
        self.assertFalse(result.evidence)
        self.assertIn("Timed out", str(result))
        self.assertNotIn("unverified partial", result.diagnostics or "")

    def test_early_eof_child_exiting_within_budget_is_not_timeout(self):
        with patch.dict(os.environ, {"PENX_LIVE_OUTPUT": "1"}), redirect_stdout(StringIO()):
            result = run_tool(_early_eof_command(0.15), timeout=5)
        self.assertEqual(result.status, "COMPLETE")
        self.assertTrue(result.evidence)
        self.assertIn("unverified partial", str(result))


if __name__ == "__main__":
    unittest.main()
