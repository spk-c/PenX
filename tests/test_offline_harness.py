"""Offline runner must never inherit an interactive console into test processes."""
from __future__ import annotations

import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

import offline_tests


class OfflineHarnessTests(unittest.TestCase):
    def test_nested_test_suites_are_not_silently_skipped(self):
        import tempfile
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            nested = root / "contracts" / "test_nested.py"
            nested.parent.mkdir()
            nested.write_text("pass\\n", encoding="utf-8")
            top_level = root / "test_root.py"
            top_level.write_text("pass\\n", encoding="utf-8")
            with patch.object(offline_tests, "TEST_ROOT", root):
                self.assertEqual(
                    set(offline_tests.discover_tests()),
                    {nested, top_level},
                )

    def test_suites_receive_closed_stdin_to_prevent_windows_key_reader_hang(self):
        with patch("offline_tests.discover_tests",
                   return_value=[Path("test_fake.py")]), \
             patch("offline_tests.subprocess.run",
                   return_value=subprocess.CompletedProcess([], 0)) as run:
            self.assertEqual(offline_tests.main([]), 0)
        self.assertEqual(run.call_count, 1)
        self.assertIs(run.call_args.kwargs["stdin"], subprocess.DEVNULL)
        self.assertFalse(run.call_args.kwargs["check"])

    def test_runner_propagates_failed_suite_result(self):
        with patch("offline_tests.discover_tests",
                   return_value=[Path("test_fake.py")]), \
             patch("offline_tests.subprocess.run",
                   return_value=subprocess.CompletedProcess([], 1)) as run:
            self.assertEqual(offline_tests.main([]), 1)
        self.assertIs(run.call_args.kwargs["stdin"], subprocess.DEVNULL)

    def test_keep_going_starts_every_suite_after_a_failure(self):
        with patch("offline_tests.discover_tests",
                   return_value=[Path("test_a.py"), Path("test_b.py")]), \
             patch("offline_tests.subprocess.run",
                   side_effect=[subprocess.CompletedProcess([], 1),
                                 subprocess.CompletedProcess([], 0)]) as run:
            self.assertEqual(offline_tests.main(["--keep-going"]), 1)
        self.assertEqual(run.call_count, 2)

    def test_fail_fast_does_not_start_suites_after_a_failure(self):
        with patch("offline_tests.discover_tests",
                   return_value=[Path("test_a.py"), Path("test_b.py")]), \
             patch("offline_tests.subprocess.run",
                   side_effect=[subprocess.CompletedProcess([], 1),
                                 subprocess.CompletedProcess([], 0)]) as run:
            self.assertEqual(offline_tests.main(["--workers", "1"]), 1)
        self.assertEqual(run.call_count, 1)

    def test_hung_suite_times_out_and_fails_the_run(self):
        with patch("offline_tests.discover_tests",
                   return_value=[Path("test_fake.py")]), \
             patch("offline_tests.subprocess.run",
                   side_effect=subprocess.TimeoutExpired(cmd=[], timeout=300)):
            self.assertEqual(offline_tests.main([]), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
