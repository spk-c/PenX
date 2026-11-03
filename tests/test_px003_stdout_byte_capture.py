"""PX-003 pre-decoding subprocess stdout capture: offline synthetic commands only."""
from __future__ import annotations

from dataclasses import replace
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from penx_app.scanners.process_runner import run_tool_with_stdout_capture
from penx_app.storage.stdout_bytes import verify_stdout_capture


def code(raw: bytes, *, stderr: bytes = b"", exit_code: int = 0) -> list[str]:
    return [sys.executable, "-c",
            f"import sys;sys.stdout.buffer.write({raw!r});"
            f"sys.stderr.buffer.write({stderr!r});sys.exit({exit_code})"]


class StdoutByteCaptureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_exact_bytes_stored_before_stripping_and_verified_against_text(self):
        raw = b"  UTF-8 \xe2\x98\x83\r\nOK  \r\n"
        result, ref = run_tool_with_stdout_capture(code(raw), self.root)
        self.assertEqual(result.status, "COMPLETE")
        self.assertEqual(str(result), raw.decode("utf-8").strip())
        self.assertEqual(ref.size_bytes, len(raw))
        self.assertEqual(ref.sha256, hashlib.sha256(raw).hexdigest())
        self.assertEqual((self.root / ref.filename).read_bytes(), raw)
        self.assertEqual(verify_stdout_capture(ref, self.root, text=str(result)), raw)
        self.assertNotEqual(ref.sha256, hashlib.sha256(str(result).encode()).hexdigest())

    def test_modified_source_with_identical_quote_is_detected(self):
        original = b"443/tcp open https\noriginal trailer\n"
        result, ref = run_tool_with_stdout_capture(code(original), self.root)
        self.assertEqual(verify_stdout_capture(ref, self.root, text=str(result)), original)
        # The quoted first line is the same, but the rest is not.
        (self.root / ref.filename).write_bytes(b"443/tcp open https\nforged trailer\n")
        with self.assertRaises(ValueError):
            verify_stdout_capture(ref, self.root, text=str(result))

    def test_decoded_text_drift_is_rejected(self):
        result, ref = run_tool_with_stdout_capture(code(b"ASCII\n"), self.root)
        with self.assertRaisesRegex(ValueError, "text"):
            verify_stdout_capture(ref, self.root, text="altered")
        self.assertEqual(verify_stdout_capture(ref, self.root, text=str(result)), b"ASCII\n")

    def test_non_utf8_output_gets_no_attestation(self):
        result, ref = run_tool_with_stdout_capture(code(b"header\xfffooter\n"), self.root)
        self.assertEqual(result.status, "PARTIAL")
        self.assertFalse(result.evidence)
        self.assertIsNone(ref)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_stderr_is_not_misrepresented_as_stdout_only(self):
        result, ref = run_tool_with_stdout_capture(code(b"ok\n", stderr=b"warning\n"),
                                                   self.root)
        self.assertEqual(result.status, "COMPLETE")
        self.assertIsNone(ref)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_nonzero_exit_timeout_cancellation_never_captures(self):
        rejected = [
            code(b"partial\n", exit_code=2),
            [sys.executable, "-c", "import time; print('partial'); time.sleep(2)"],
        ]
        for n, command in enumerate(rejected):
            with self.subTest(n=n):
                result, ref = run_tool_with_stdout_capture(
                    command, self.root, timeout=1)
                self.assertNotEqual(result.status, "COMPLETE")
                self.assertIsNone(ref)
        event=threading.Event()
        event.set()
        with patch("subprocess.Popen", side_effect=AssertionError("should not spawn")):
            result, ref = run_tool_with_stdout_capture(code(b"sample"), self.root,
                                                        cancel_event=event)
        self.assertEqual(result.status, "PARTIAL")
        self.assertIsNone(ref)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_truncated_source_never_becomes_complete_provenance(self):
        from penx_app.scanners.process_runner import MAX_CAPTURE_BYTES
        command=[sys.executable, "-c", "import sys;sys.stdout.buffer.write(b'A'*"
                 + str(MAX_CAPTURE_BYTES+1) + ")"]
        result, ref=run_tool_with_stdout_capture(command,self.root)
        self.assertEqual(result.status,"PARTIAL")
        self.assertIsNone(ref)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_corrupt_missing_and_symlinked_file_fail_closed(self):
        result, ref=run_tool_with_stdout_capture(code(b"source\n"), self.root)
        path=self.root / ref.filename
        path.unlink()
        with self.assertRaises(OSError):
            verify_stdout_capture(ref,self.root,text=str(result))
        target=self.root / "replacement-source.bin"
        target.write_bytes(b"source\n")
        # The original digest-named file is now a symlink; hash equality
        # must not bypass the path-integrity guard.
        try:
            path.symlink_to(target)
        except (OSError, NotImplementedError):
            return
        with self.assertRaises(ValueError):
            verify_stdout_capture(ref,self.root,text=str(result))

    def test_bounded_ref_rejects_forged_claims(self):
        result, ref=run_tool_with_stdout_capture(code(b"source\n"), self.root)
        with self.assertRaises(ValueError):
            replace(ref, sha256="g"*64)
        with self.assertRaises(ValueError):
            replace(ref, size_bytes=True)
        with self.assertRaises(ValueError):
            replace(ref, filename="../secret.bin")
        with self.assertRaises(ValueError):
            replace(ref, validator="sha256-utf8-v1")

    def test_repeated_capture_does_not_overwrite_first_file(self):
        first, ref_one = run_tool_with_stdout_capture(code(b"identical\n"), self.root)
        second, ref_two = run_tool_with_stdout_capture(code(b"identical\n"), self.root)
        self.assertNotEqual(ref_one.filename, ref_two.filename)
        self.assertEqual(verify_stdout_capture(ref_one, self.root, text=str(first)),
                         b"identical\n")
        self.assertEqual(verify_stdout_capture(ref_two, self.root, text=str(second)),
                         b"identical\n")

    def test_live_rendering_matches_quiet_capture_without_network(self):
        from io import StringIO
        from contextlib import redirect_stdout
        with patch("penx_app.scanners.process_runner.live_output",
                   return_value=True), redirect_stdout(StringIO()):
            output, ref = run_tool_with_stdout_capture(
                code(b"live scanner fixture\r\n"), self.root)
        self.assertEqual(output.status, "COMPLETE")
        self.assertEqual(verify_stdout_capture(ref, self.root, text=str(output)),
                         b"live scanner fixture\r\n")

    def test_capture_publication_failure_not_reported_as_verified(self):
        with patch("penx_app.storage.stdout_bytes.publish_unique",
                   side_effect=PermissionError("synthetic filesystem denial")):
            with self.assertRaises(PermissionError):
                run_tool_with_stdout_capture(code(b"private fixture\n"), self.root)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_default_run_tool_does_not_write_any_capture(self):
        from penx_app.scanners.process_runner import run_tool
        with patch("penx_app.file_output.publish_unique",
                   side_effect=AssertionError("not opted in")):
            result = run_tool(code(b"clean\n"))
        self.assertEqual(result.status, "COMPLETE")
        self.assertEqual(list(self.root.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
