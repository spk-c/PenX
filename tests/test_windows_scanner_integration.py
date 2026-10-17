"""Win32 scanner-process smoke tests using real disposable Python children.

These exercise actual CreateProcess/taskkill behavior on GitHub windows-latest,
not simulated Win32 calls. No Npcap, UAC or external target is involved.
"""
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


@unittest.skipUnless(os.name == "nt", "requires a real Windows runner")
class WindowsScannerIntegrationTests(unittest.TestCase):
    def test_live_and_quiet_success_use_real_process(self):
        for live in (False, True):
            with self.subTest(live=live), patch.dict(
                    os.environ, {"PENX_LIVE_OUTPUT": "1" if live else "0"}
            ), redirect_stdout(StringIO()):
                result = run_tool(
                    [sys.executable, "-c", "print('fixture-scanner-ready',flush=True)"],
                    timeout=8,
                )
                self.assertEqual(result.status, "COMPLETE")
                self.assertTrue(result.evidence)
                self.assertEqual(result.exit_code, 0)
                self.assertIn("fixture-scanner-ready", str(result))

    def test_windows_process_tree_cancel_removes_descendant(self):
        with tempfile.TemporaryDirectory(prefix="penx-win-scanner-") as root:
            folder = Path(root)
            started = folder / "scanner-started"
            orphan = folder / "orphan-marker"
            child = (
                "import os,pathlib,time;"
                "time.sleep(2.0);"
                "pathlib.Path(os.environ['PENX_TEST_ORPHAN']).write_text('orphaned')"
            )
            parent = (
                "import pathlib,subprocess,sys,time;"
                "subprocess.Popen([sys.executable,'-c'," + repr(child) + "]);"
                "pathlib.Path(" + repr(str(started)) + ").write_text('ready');"
                "print('fixture scanner started',flush=True);time.sleep(20)"
            )
            env = dict(os.environ, PENX_TEST_ORPHAN=str(orphan))
            cancel = threading.Event()
            collected = []
            errors = []

            def run():
                try:
                    collected.append(run_tool(
                        [sys.executable, "-c", parent],
                        timeout=12, env=env, cancel_event=cancel,
                    ))
                except BaseException as exc:
                    errors.append(exc)

            thread = threading.Thread(target=run, daemon=True)
            with patch.dict(os.environ, {"PENX_LIVE_OUTPUT": "1"}), redirect_stdout(StringIO()):
                thread.start()
                try:
                    deadline = time.monotonic() + 8
                    while not started.exists() and time.monotonic() < deadline:
                        time.sleep(0.03)
                finally:
                    cancel.set()
                    thread.join(timeout=8)
            self.assertTrue(started.exists(), "Windows scanner subprocess did not start")
            self.assertFalse(thread.is_alive(), "Cancellation did not stop Windows process")
            self.assertEqual(errors, [])
            self.assertEqual(len(collected), 1)
            self.assertEqual(collected[0].status, "PARTIAL")
            self.assertFalse(collected[0].evidence)
            time.sleep(2.2)
            self.assertFalse(orphan.exists(), "Windows taskkill left a scanner descendant")


if __name__ == "__main__":
    unittest.main()
