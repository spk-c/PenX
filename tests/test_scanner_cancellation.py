"""Cancellation and live-mode timeout clean up the whole scanner process tree.

The quiet-mode timeout path is pinned by ``test_scanner_process_tree``;
these contracts cover the remaining two termination routes in
``process_runner``: the caller-cancellation (``BaseException``) path and
the live-mode timeout path.
"""
from __future__ import annotations

from contextlib import redirect_stdout
from io import StringIO
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from penx_app.scanners import process_runner
from penx_app.scanners.process_runner import run_tool


def _tree_commands(root: Path, spawn_marker: Path) -> tuple[str, dict]:
    """Parent spawns a grandchild that writes a marker unless killed early."""
    child = (
        "import os, pathlib, time; time.sleep(3.0); "
        "pathlib.Path(os.environ['PENX_TEST_SENTINEL_PATH']).write_text('survived')"
    )
    parent = (
        "import pathlib, subprocess, sys, time; "
        "subprocess.Popen([sys.executable, '-c', " + repr(child) + "]); "
        "pathlib.Path(" + repr(str(spawn_marker)) + ").write_text('spawned'); "
        "print('child spawned', flush=True); "
        "time.sleep(20)"
    )
    environment = dict(
        os.environ,
        PENX_TEST_SENTINEL_PATH=str(root / "orphan-wrote-file.txt"),
    )
    return parent, environment


class ScannerCancellationContracts(unittest.TestCase):
    def test_caller_cancellation_terminates_process_tree(self):
        with tempfile.TemporaryDirectory(prefix="penx-cancel-") as root:
            root_path = Path(root)
            spawn_marker = root_path / "child-spawned.txt"
            orphan = root_path / "orphan-wrote-file.txt"
            parent, environment = _tree_commands(root_path, spawn_marker)

            class CallerCancelled(BaseException):
                pass

            real_wait = subprocess.Popen.wait
            cancelled = False

            def wait_once(self, timeout=None):
                nonlocal cancelled
                if not cancelled:
                    # Wait until the parent has actually spawned its child,
                    # then simulate the caller abandoning the run.
                    deadline = time.monotonic() + 10
                    while not spawn_marker.exists() and time.monotonic() < deadline:
                        time.sleep(0.01)
                    cancelled = True
                    raise CallerCancelled
                return real_wait(self, timeout)

            baseline = threading.active_count()
            with patch.dict(os.environ, {"PENX_LIVE_OUTPUT": "0"}), \
                    patch.object(subprocess.Popen, "wait", wait_once):
                with self.assertRaises(CallerCancelled):
                    run_tool([sys.executable, "-c", parent],
                             timeout=10, env=environment)
            self.assertTrue(spawn_marker.exists())
            # The drain threads must be joined before the exception returns.
            self.assertEqual(threading.active_count(), baseline)
            # Without tree cleanup the grandchild would have written at ~3s.
            time.sleep(3.3)
            self.assertFalse(orphan.exists(), "Cancellation orphaned scanner child")

    def test_live_timeout_kills_descendants(self):
        with tempfile.TemporaryDirectory(prefix="penx-live-tree-") as root:
            root_path = Path(root)
            orphan = root_path / "orphan-wrote-file.txt"
            parent, environment = _tree_commands(root_path, root_path / "spawned")
            with patch.dict(os.environ, {"PENX_LIVE_OUTPUT": "1"}), \
                    redirect_stdout(StringIO()):
                result = run_tool([sys.executable, "-c", parent],
                                  timeout=1, env=environment)
            self.assertEqual(result.status, "PARTIAL")
            self.assertFalse(result.evidence)
            self.assertIn("Timed out", str(result))
            time.sleep(3.3)
            self.assertFalse(orphan.exists(), "Live timeout orphaned scanner child")

    def test_terminate_tree_is_idempotent_for_exited_process(self):
        proc = subprocess.Popen([sys.executable, "-c", "pass"])
        proc.wait()
        # Re-termination (e.g. timeout handler after an early exit) must not
        # raise or alter the recorded exit code.
        process_runner._terminate_process_tree(proc)
        process_runner._terminate_process_tree(proc)
        self.assertEqual(proc.returncode, 0)


if __name__ == "__main__":
    unittest.main()
