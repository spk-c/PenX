"""Report publication manifest reads must be bounded to one verified file.

Only disposable local files; no scanners, LLMs, databases or HTTP requests.
"""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from penx_app.reporting import report_batch as batch


class PublicationManifestReadSafetyTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="penx-manifest-reader-")
        self.addCleanup(tmp.cleanup)
        self.folder = Path(tmp.name)
        self.manifest = batch._manifest_path(self.folder, 7)

    def test_valid_manifest_states_still_work(self):
        batch.begin_publication(self.folder, 7, ("html", "pdf"))
        self.assertEqual(batch.publication_state(self.folder, 7)["status"], "in_progress")
        batch.finalize_publication(self.folder, 7, {"html": self.folder / "out.html"}, {})
        self.assertEqual(batch.publication_state(self.folder, 7)["status"], "complete")

    def test_missing_and_broken_json_are_unknown(self):
        self.assertIsNone(batch.publication_state(self.folder, 7))
        self.manifest.write_text("not json", encoding="utf-8")
        self.assertIsNone(batch.publication_state(self.folder, 7))

    def test_oversized_file_is_not_parsed(self):
        self.manifest.write_bytes(b" " * 65537)
        with patch.object(batch.json, "loads",
                          side_effect=AssertionError("should not parse")):
            self.assertIsNone(batch.publication_state(self.folder, 7))

    def test_actual_bytes_are_bounded_even_if_fstat_size_is_stale(self):
        self.manifest.write_bytes(b"x" * 65537)
        original = os.fstat

        def stale(fd):
            actual = original(fd)
            class Stat:
                st_dev = actual.st_dev
                st_ino = actual.st_ino
                st_mode = actual.st_mode
                st_size = 1
            return Stat()

        with patch.object(batch.os, "fstat", side_effect=stale), \
             patch.object(batch.json, "loads",
                          side_effect=AssertionError("should not parse")):
            self.assertIsNone(batch.publication_state(self.folder, 7))

    def test_symlink_manifest_is_not_read(self):
        target = self.folder / "outside.json"
        target.write_text('{"schema":"penx-publication-v1","session":7,'
                          '"status":"complete"}', encoding="utf-8")
        try:
            self.manifest.symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest("Symlink creation not permitted")
        self.assertIsNone(batch.publication_state(self.folder, 7))

    def test_replaced_file_identity_is_rejected(self):
        self.manifest.write_text('{"schema":"penx-publication-v1","session":7,'
                                 '"status":"complete"}', encoding="utf-8")
        original_lstat = Path.lstat

        def changed(path):
            record = original_lstat(path)
            if path == self.manifest:
                class Replaced:
                    st_dev = record.st_dev
                    st_ino = record.st_ino + 1
                    st_mode = record.st_mode
                return Replaced()
            return record

        with patch.object(Path, "lstat", changed):
            self.assertIsNone(batch.publication_state(self.folder, 7))


if __name__ == "__main__":
    unittest.main()
