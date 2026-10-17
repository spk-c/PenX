"""ffuf wordlists must be size-bounded at read time, without symlink races.

No actual ffuf process, network activity or external files.
"""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from penx_app.scanners import native_web_scanners as native


class FfufWordlistReadContracts(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="penx-ffuf-wordlist-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.path = self.root / "paths.txt"
        environ = patch.dict(os.environ, {"PENX_FFUF_WORDLIST": str(self.path)})
        environ.start()
        self.addCleanup(environ.stop)

    def test_valid_bom_comments_and_duplicates_are_preserved(self):
        self.path.write_text("# comment\nadmin\nlogin\nadmin\n", encoding="utf-8-sig")
        self.assertEqual(native.ffuf_words(), ["admin", "login"])

    def test_oversized_file_is_rejected_before_parsing(self):
        self.path.write_bytes(b"x" * 8193)
        with self.assertRaisesRegex(ValueError, "larger than 8 KiB"):
            native.ffuf_words()

    def test_growing_file_is_still_rejected_when_metadata_looks_small(self):
        self.path.write_bytes(b"b" * 8193)
        original = os.fstat

        def stale(fd):
            info = original(fd)
            class Stats:
                st_mode = info.st_mode
                st_dev = info.st_dev
                st_ino = info.st_ino
                st_size = 1
            return Stats()

        with patch.object(native.os, "fstat", side_effect=stale):
            with self.assertRaisesRegex(ValueError, "larger than 8 KiB"):
                native.ffuf_words()

    def test_symlink_to_wordlist_is_not_opened(self):
        original = self.root / "legitimate.txt"
        original.write_text("robots.txt\n", encoding="utf-8")
        try:
            self.path.symlink_to(original)
        except (OSError, NotImplementedError):
            self.skipTest("Symbolic links unavailable")
        with self.assertRaises(ValueError):
            native.ffuf_words()
        self.assertEqual(original.read_text(encoding="utf-8"), "robots.txt\n")

    def test_missing_file_fails_without_running_scan(self):
        with self.assertRaisesRegex(ValueError, "missing"):
            native.ffuf_words()

    def test_over_80_distinct_paths_remains_rejected(self):
        self.path.write_text("\n".join("p" + str(i) for i in range(81)),
                             encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "80 unique"):
            native.ffuf_words()


if __name__ == "__main__":
    unittest.main()
