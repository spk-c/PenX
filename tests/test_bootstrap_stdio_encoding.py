"""Offline coverage for UTF-8 text-stream protection in bootstrap and process_runner.

German Windows redirects stdout to cp1252 ("charmap"); non-Latin characters in
scanner or model output must not crash a scan run or a dispatch path.
"""
import io
import sys
import unittest


def _cp1252_stream() -> io.TextIOWrapper:
    return io.TextIOWrapper(io.BytesIO(), encoding="cp1252", errors="strict", newline="\n")


class ForceUtf8StreamsTests(unittest.TestCase):
    def test_cp1252_stream_is_reconfigured_to_utf8(self):
        from penx_app.bootstrap import _force_utf8_text_streams
        stream = _cp1252_stream()
        _force_utf8_text_streams((stream,))
        self.assertEqual(stream.encoding, "utf-8")
        stream.write("✓ Katana scan\n")
        stream.flush()
        self.assertEqual(stream.buffer.getvalue(), "✓ Katana scan\n".encode("utf-8"))

    def test_non_reconfigurable_stream_is_ignored(self):
        from penx_app.bootstrap import _force_utf8_text_streams
        stream = io.StringIO()  # no reconfigure() attribute
        _force_utf8_text_streams((stream,))  # must not raise
        stream.write("ok")

    def test_main_dispatch_reconfigures_redirected_stdout(self):
        from penx_app import bootstrap
        stream = _cp1252_stream()
        old_stdout, old_argv = sys.stdout, sys.argv
        sys.stdout = stream
        sys.argv = ["penx.py", "--version"]
        try:
            rc = bootstrap.main()
        finally:
            sys.stdout, sys.argv = old_stdout, old_argv
        stream.flush()
        data = stream.buffer.getvalue().decode("utf-8")
        stream.close()
        self.assertEqual(rc, 0)
        self.assertEqual(stream.encoding, "utf-8")
        self.assertIn("PenX Windows", data)


class LiveLineEmissionTests(unittest.TestCase):
    def test_unencodable_character_falls_back_to_ascii(self):
        from penx_app.scanners.process_runner import _emit_line
        stream = _cp1252_stream()
        old = sys.stdout
        sys.stdout = stream
        try:
            _emit_line("  [SCAN] ✓ done")  # must not raise
        finally:
            sys.stdout = old
        data = stream.buffer.getvalue()
        stream.close()
        self.assertIn(b"[SCAN]", data)
        self.assertNotIn("✓".encode("utf-8"), data)

    def test_utf8_stream_passes_through(self):
        from penx_app.scanners.process_runner import _emit_line
        stream = io.TextIOWrapper(io.BytesIO(), encoding="utf-8", errors="strict", newline="\n")
        old = sys.stdout
        sys.stdout = stream
        try:
            _emit_line("  [SCAN] ✓ done")
        finally:
            sys.stdout = old
        data = stream.buffer.getvalue()
        stream.close()
        self.assertIn("✓ done".encode("utf-8"), data)


if __name__ == "__main__":
    unittest.main()
