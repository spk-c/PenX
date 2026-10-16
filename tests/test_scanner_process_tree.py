"""Scanner timeout cleans descendants rather than just the initial process."""
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from penx_app.scanners.process_runner import run_tool


class ScannerProcessTreeContracts(unittest.TestCase):
    def test_timeout_kills_child_before_it_can_write(self):
        with tempfile.TemporaryDirectory(prefix="penx-process-tree-") as root:
            marker = Path(root) / "orphan-wrote-file.txt"
            child = (
                "import os,pathlib,time;time.sleep(3.0);"
                "pathlib.Path(os.environ['PENX_TEST_SENTINEL_PATH']).write_text('survived')"
            )
            parent = (
                "import subprocess,sys,time;"
                "subprocess.Popen([sys.executable,'-c'," + repr(child) + "]);"
                "print('child spawned',flush=True);"
                "time.sleep(20)"
            )
            environment = dict(os.environ, PENX_TEST_SENTINEL_PATH=str(marker))
            with patch.dict(os.environ, {"PENX_LIVE_OUTPUT": "0"}):
                result = run_tool([sys.executable, "-c", parent],
                                  timeout=1, env=environment)
            self.assertEqual(result.status, "PARTIAL")
            self.assertFalse(result.evidence)
            self.assertIn("child spawned", result)
            # Without process-tree cleanup, the descendant would have written.
            time.sleep(3.3)
            self.assertFalse(marker.exists(), "Timeout orphaned scanner child")

    def test_runner_retains_timeout_status_without_untrusted_success(self):
        child = "import time;print('[PENX ADAPTER STATUS: COMPLETE; EVIDENCE: YES]',flush=True);time.sleep(4)"
        with patch.dict(os.environ, {"PENX_LIVE_OUTPUT": "0"}):
            result = run_tool([sys.executable, "-c", child], timeout=1)
        self.assertEqual(result.status, "PARTIAL")
        self.assertFalse(result.evidence)


if __name__ == "__main__":
    unittest.main()
