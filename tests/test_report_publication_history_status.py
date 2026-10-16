"""Read-only recovery hints for interrupted and partial report publication."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from penx_app.cli.history_dialog import view_history
from penx_app.reporting.report_batch import (
    _manifest_path, begin_publication, finalize_publication,
)
from penx_app.reporting.report_management import publication_status


class ManifestHistoryStatusTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.folder = Path(self.tmp.name)

    def state(self):
        return publication_status(7, "fixture.test", directory=self.folder)

    def test_missing_and_corrupt_manifest_are_not_trusted(self):
        self.assertIsNone(self.state())
        manifest = _manifest_path(self.folder, 7)
        manifest.write_text("{bad-json", encoding="utf-8")
        self.assertIsNone(self.state())
        manifest.write_text('{"schema": "penx-publication-v1", '
                            '"session": 999, "status": "in_progress"}',
                            encoding="utf-8")
        self.assertIsNone(self.state())
        manifest.write_text('{"schema": "unexpected", '
                            '"session": 7, "status": "complete"}',
                            encoding="utf-8")
        self.assertIsNone(self.state())

    def test_report_manifest_status_is_read_only_and_session_scoped(self):
        begin_publication(self.folder, 7, ("html", "pdf"))
        self.assertEqual(self.state(), "in_progress")
        other = _manifest_path(self.folder, 8)
        self.assertFalse(other.exists())
        finalize_publication(self.folder, 7, {"html": self.folder / "out.html"},
                             {"pdf": "synthetic error"})
        self.assertEqual(self.state(), "partial")
        finalize_publication(self.folder, 7, {"html": self.folder / "out.html",
                                               "pdf": self.folder / "out.pdf"}, {})
        self.assertEqual(self.state(), "complete")
        self.assertFalse(other.exists())

    def test_manifest_symlink_is_not_read(self):
        manifest = _manifest_path(self.folder, 7)
        outside = self.folder / "outside.json"
        outside.write_text('{"schema":"penx-publication-v1","session":7,'
                           '"status":"in_progress"}', encoding="utf-8")
        try:
            manifest.symlink_to(outside)
        except (OSError, NotImplementedError):
            self.skipTest("This Windows runner does not permit symlinks")
        with self.assertRaises(OSError):
            self.state()
        self.assertTrue(outside.is_file())


class ReportHistoryWarningTests(unittest.TestCase):
    def make_ports(self, status):
        prompts = iter(("7", "0"))
        return {
            "divider": Mock(),
            "get_all_history": Mock(return_value=[(7, "fixture.test", "today", "active")]),
            "warn": Mock(),
            "print_history": Mock(),
            "show_back": Mock(),
            "prompt": Mock(side_effect=lambda *_a, **_kw: next(prompts)),
            "is_back": lambda choice: choice in ("0", "back", "esc"),
            "error": Mock(),
            "get_session": Mock(return_value={
                "history": (7, "fixture.test", "today", "active")}),
            "_session_is_active": lambda history: bool(history and history[3] == "active"),
            "print_session": Mock(),
            "existing_reports": Mock(return_value={}),
            "info": Mock(),
            "generate_session_reports": Mock(),
            "generate_session_reports_independent": Mock(),
            "success": Mock(),
            "confirm": Mock(),
            "delete_session_reports": Mock(),
            "edit_delete_menu": Mock(),
            "delete_full_session": Mock(),
            "publication_status": Mock(return_value=status),
        }

    def test_interrupted_state_warns_without_automatic_regeneration(self):
        ports = self.make_ports("in_progress")
        view_history(**ports)
        self.assertTrue(any("interrupted" in args.args[0] for args
                            in ports["warn"].call_args_list))
        ports["generate_session_reports_independent"].assert_not_called()
        ports["delete_full_session"].assert_not_called()

    def test_partial_state_warns_and_complete_state_does_not(self):
        ports = self.make_ports("partial")
        view_history(**ports)
        self.assertTrue(any("incomplete" in args.args[0] for args
                            in ports["warn"].call_args_list))
        clean = self.make_ports("complete")
        view_history(**clean)
        clean["warn"].assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
