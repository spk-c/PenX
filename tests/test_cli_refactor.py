"""CLI and scan-recovery refactor behavioral compatibility regression tests."""
from __future__ import annotations

from pathlib import Path
import json
import os
import tempfile
import unittest
from unittest.mock import patch

from penx_app.cli import cli_views
import penx
from penx_app.application import scan_recovery


class CliRefactorTests(unittest.TestCase):
    def test_public_penx_facades_keep_view_semantics(self):
        row = (7, 3, "Example", "medium", "likely", "443", "https")
        self.assertEqual(penx.format_vulnerability_picker(row),
                         cli_views.format_vulnerability_picker(row))
        self.assertTrue(penx._session_is_active((1, "host", "date", "active")))
        self.assertFalse(penx._session_is_active((1, "host", "date", "pending")))

    def test_recovery_files_exclusive_and_lossless(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = [
                scan_recovery.save_unanalysed_recon(root, 4, "nmap evidence"),
                scan_recovery.save_unanalysed_recon(root, 4, "repeated result"),
            ]
            self.assertNotEqual(*paths)
            self.assertEqual(paths[0].read_text(encoding="utf-8"), "nmap evidence")
            self.assertEqual(paths[1].read_text(encoding="utf-8"), "repeated result")
            if os.name != "nt":  # POSIX mode bits do not reflect Windows ACLs.
                self.assertEqual(paths[0].stat().st_mode & 0o077, 0)

    def test_assessment_saved_as_json_and_notice_can_be_injected(self):
        with tempfile.TemporaryDirectory() as directory:
            notes = []
            result = {"risk_level": "LOW", "scan": "example.test"}
            path = scan_recovery.save_unsaved_assessment(
                Path(directory), 9, result, notify=notes.append)
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), result)
            self.assertIn(str(path), notes[0])

    def test_penx_wrapper_preserves_patchable_location(self):
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(penx, "APP_ROOT", Path(directory)), \
             patch.object(penx, "warn") as notification:
            p = penx.preserve_failed_recon(19, "raw scan")
            a = penx.preserve_failed_assessment(19, {"summary": "unsaved"})
            self.assertTrue(p.exists())
            self.assertTrue(a.exists())
            notification.assert_called_once()


if __name__ == "__main__":
    unittest.main(verbosity=2)
