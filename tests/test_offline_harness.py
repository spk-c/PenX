"""Offline test runner contracts: bounded capture, cancellation, timeout and fail-fast."""
from __future__ import annotations

import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import offline_tests


class OfflineHarnessTests(unittest.TestCase):
    def test_nested_test_suites_are_not_silently_skipped(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            nested = root / "contracts" / "test_nested.py"
            nested.parent.mkdir()
            nested.write_text("pass\n", encoding="utf-8")
            top_level = root / "test_root.py"
            top_level.write_text("pass\n", encoding="utf-8")
            with patch.object(offline_tests, "TEST_ROOT", root):
                self.assertEqual(set(offline_tests.discover_tests()),
                                 {nested, top_level})

    def test_child_stdin_is_closed_and_output_is_captured(self):
        with tempfile.TemporaryDirectory() as directory:
            child = Path(directory) / "test_stdin.py"
            child.write_text("import sys\nprint(repr(sys.stdin.read()))\n", encoding="utf-8")
            rc, out, err, failure = offline_tests._run_suite(child, os.environ.copy())
        self.assertEqual((rc, err, failure), (0, b"", None))
        self.assertIn(b"''", out)

    def test_runner_propagates_failed_suite_result(self):
        with patch("offline_tests.discover_tests",
                   return_value=[Path("test_fake.py")]), \
             patch("offline_tests._run_suite",
                   return_value=(1, b"", b"", None)):
            self.assertEqual(offline_tests.main([]), 1)

    def test_keep_going_starts_every_suite_after_a_failure(self):
        with patch("offline_tests.discover_tests",
                   return_value=[Path("test_a.py"), Path("test_b.py")]), \
             patch("offline_tests._run_suite",
                   side_effect=[(1, b"", b"", None), (0, b"", b"", None)]) as run:
            self.assertEqual(offline_tests.main(["--workers", "1", "--keep-going"]), 1)
        self.assertEqual(run.call_count, 2)

    def test_fail_fast_does_not_start_suites_after_a_failure(self):
        with patch("offline_tests.discover_tests",
                   return_value=[Path("test_a.py"), Path("test_b.py")]), \
             patch("offline_tests._run_suite",
                   side_effect=[(1, b"", b"", None), (0, b"", b"", None)]) as run:
            self.assertEqual(offline_tests.main(["--workers", "1"]), 1)
        self.assertEqual(run.call_count, 1)

    def test_output_capture_is_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            child = Path(directory) / "test_output.py"
            child.write_text("import sys\nsys.stdout.write('x' * 100000)\n",
                             encoding="utf-8")
            with patch.object(offline_tests, "MAX_SUITE_OUTPUT_BYTES", 1024):
                rc, out, err, failure = offline_tests._run_suite(child, os.environ.copy())
        self.assertEqual((rc, err, failure), (0, b"", None))
        self.assertEqual(len(out), 1024)

    def test_large_output_keeps_tail_with_final_error(self):
        from offline_tests import _BoundedOutput
        output = _BoundedOutput(1024)
        output.append(b"START\\n" + b"x" * 100000)
        output.append(b"\\nFINAL TRACEBACK MARKER\\n")
        captured = output.output()
        self.assertEqual(len(captured), 1024)
        self.assertIn(b"START", captured)
        self.assertIn(b"middle test output omitted", captured)
        self.assertIn(b"FINAL TRACEBACK MARKER", captured)

    def test_normal_output_keeps_exact_bytes(self):
        from offline_tests import _BoundedOutput
        output = _BoundedOutput(1024)
        output.append(b"first")
        output.append(b" second\\n")
        self.assertEqual(output.output(), b"first second\\n")

    def test_hung_suite_times_out_and_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            child = Path(directory) / "test_sleep.py"
            child.write_text("import time\ntime.sleep(10)\n", encoding="utf-8")
            with patch.object(offline_tests, "SUITE_TIMEOUT_SECONDS", 0.2):
                code, _, _, error = offline_tests._run_suite(child, os.environ.copy())
        self.assertEqual(code, 124)
        self.assertIn("timed out", error)

    def test_fail_fast_cancels_an_already_running_suite(self):
        with tempfile.TemporaryDirectory() as directory:
            failing = Path(directory) / "test_failing.py"
            sleeping = Path(directory) / "test_sleeping.py"
            failing.write_text("import time\ntime.sleep(0.15)\nraise SystemExit(1)\n",
                               encoding="utf-8")
            sleeping.write_text("import time\ntime.sleep(8)\n", encoding="utf-8")
            begin = time.monotonic()
            with patch("offline_tests.discover_tests", return_value=[failing, sleeping]):
                result = offline_tests.main(["--workers", "2"])
            elapsed = time.monotonic() - begin
        self.assertEqual(result, 1)
        self.assertLess(elapsed, 5.0, "fail-fast left a child suite running")


if __name__ == "__main__":
    unittest.main(verbosity=2)
