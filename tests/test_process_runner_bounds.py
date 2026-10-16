"""Bounded scanner processes must drain both pipes and downgrade truncation."""
from __future__ import annotations

from contextlib import redirect_stdout
from io import StringIO
import os
import sys
import unittest
from unittest.mock import patch

from penx_app.scanners.process_runner import MAX_CAPTURE_BYTES, run_tool


class ProcessBoundTests(unittest.TestCase):
    def test_long_stdout_is_drained_but_not_trusted(self):
        cmd = [sys.executable, "-c",
               f"import sys;sys.stdout.write('A'*({MAX_CAPTURE_BYTES}+32768))"]
        result = run_tool(cmd, timeout=10)
        self.assertEqual(result.status, "PARTIAL")
        self.assertFalse(result.evidence)
        self.assertIn("OUTPUT TRUNCATED", result)
        self.assertLess(len(result), MAX_CAPTURE_BYTES + 1024)

    def test_large_stderr_never_blocks_process(self):
        cmd = [sys.executable, "-c",
               f"import sys;sys.stderr.write('E'*({MAX_CAPTURE_BYTES}+8192))"]
        result = run_tool(cmd, timeout=10)
        self.assertEqual(result.status, "PARTIAL")
        self.assertFalse(result.evidence)
        self.assertIn("OUTPUT TRUNCATED", result)

    def test_stdout_and_stderr_are_both_collected_and_decoded(self):
        cmd = [sys.executable, "-c",
               "import sys;print('✓ output');print('⚠ diagnostic',file=sys.stderr)"]
        result = run_tool(cmd, timeout=10)
        self.assertEqual(result.status, "COMPLETE")
        self.assertIn("✓ output", result)
        self.assertIn("⚠ diagnostic", result)

    def test_live_line_without_newline_is_bounded(self):
        cmd = [sys.executable, "-c",
               f"import sys;sys.stdout.write('X'*({MAX_CAPTURE_BYTES}+8192))"]
        output = StringIO()
        with patch.dict(os.environ, {"PENX_LIVE_OUTPUT": "1"}), redirect_stdout(output):
            result = run_tool(cmd, timeout=10)
        self.assertEqual(result.status, "PARTIAL")
        self.assertFalse(result.evidence)
        self.assertIn("OUTPUT TRUNCATED", result)
        self.assertLess(len(result), MAX_CAPTURE_BYTES + 1024)


if __name__ == "__main__":
    unittest.main()
