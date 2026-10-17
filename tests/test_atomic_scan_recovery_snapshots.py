"""Crash-safe recovery snapshots using only disposable local directories.

These tests never access production databases, scanner processes or HTTP.
"""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from penx_app.application.scan_recovery import (
    save_unanalysed_recon, save_unsaved_assessment,
)


class AtomicRecoverySnapshotsTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="penx-recovery-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.folder = self.root / "reports"

    def test_complete_scan_snapshot_never_overwrites_retry_or_symlink(self):
        first = save_unanalysed_recon(self.root, 17, "Nmap done: one host")
        second = save_unanalysed_recon(self.root, 17, "Nmap done: two hosts")
        self.assertEqual(first.name, "recon_SL17_unanalysed.txt")
        self.assertEqual(second.name, "recon_SL17_unanalysed_1.txt")
        self.assertEqual(first.read_text(encoding="utf-8"), "Nmap done: one host")
        self.assertEqual(second.read_text(encoding="utf-8"), "Nmap done: two hosts")
        self.assertFalse(any(p.name.startswith(".penx-stage-") for p in self.folder.iterdir()))

    def test_json_snapshot_is_complete_and_notifies_only_after_publish(self):
        notification = Mock()
        result = {"risk_level": "LOW", "summary": "Übersicht ✓"}
        first = save_unsaved_assessment(self.root, 3, result, notify=notification)
        second = save_unsaved_assessment(self.root, 3, result)
        self.assertEqual(first.name, "assessment_SL3_unsaved.json")
        self.assertEqual(second.name, "assessment_SL3_unsaved_1.json")
        self.assertEqual(json.loads(first.read_text(encoding="utf-8")), result)
        notification.assert_called_once()
        self.assertIn(str(first), notification.call_args.args[0])

    def test_serialization_failure_creates_no_partial_final_or_temporary_file(self):
        data: dict = {}
        data["cycle"] = data
        with self.assertRaises(ValueError):
            save_unsaved_assessment(self.root, 3, data)
        self.assertFalse(self.folder.exists() and any(self.folder.iterdir()))

    def test_staging_encoding_failure_leaves_no_corrupt_recovery_file(self):
        # A lone surrogate cannot be encoded as UTF-8; a direct final-name
        # write would leave an empty/truncated recovery artifact behind.
        with self.assertRaises(UnicodeEncodeError):
            save_unanalysed_recon(self.root, 5, "valid\ud800")
        self.assertFalse(any(self.folder.iterdir()))

    def test_failed_atomic_link_does_not_publish_or_notify(self):
        notify = Mock()
        with patch("penx_app.file_output.os.link", side_effect=OSError("simulated disk failure")):
            with self.assertRaises(OSError):
                save_unsaved_assessment(self.root, 3, {"summary": "valid"}, notify=notify)
        notify.assert_not_called()
        self.assertEqual(list(self.folder.iterdir()), [])

    def test_invalid_session_id_does_not_create_any_file(self):
        for invalid in (0, -2, True, "1", "../outside"):
            with self.subTest(value=invalid):
                with self.assertRaises(ValueError):
                    save_unanalysed_recon(self.root, invalid, "synthetic")
                with self.assertRaises(ValueError):
                    save_unsaved_assessment(self.root, invalid, {"safe": True})
        self.assertFalse(self.folder.exists())

    def test_nontext_scan_output_does_not_create_a_false_recovery(self):
        with self.assertRaises(TypeError):
            save_unanalysed_recon(self.root, 1, None)
        with self.assertRaises(TypeError):
            save_unsaved_assessment(self.root, 1, ["not an assessment"])
        self.assertFalse(self.folder.exists())


if __name__ == "__main__":
    unittest.main()
