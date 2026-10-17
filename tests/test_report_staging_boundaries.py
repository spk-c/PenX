"""Report staging must not turn renderer mistakes into file moves or links.

Only local temporary files are used. No scanners, databases or network targets.
"""
from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from penx_app.reporting import report_batch
from penx_app.reporting import report_management


class ReportStagingBoundaries(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="penx-stage-boundary-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.folder = self.root / "reports"
        self.folder.mkdir()
        self.outside = self.root / "original.txt"
        self.outside.write_text("never move or expose this file", encoding="utf-8")
        self.targets = {
            "html": self.folder / "penx_SL7_fixture.html",
            "pdf": self.folder / "penx_SL7_fixture.pdf",
        }
        self.data = {
            "history": (7, "fixture.test", "today", "active"),
            "summary": (1, 7, "raw", "analysis", "LOW", "local", "today"),
            "vulns": [], "fixes": [], "corrections": [],
        }

    def link(self, directory):
        link = Path(directory) / "staged.html"
        try:
            link.symlink_to(self.outside)
        except (OSError, NotImplementedError):
            self.skipTest("File symlinks unavailable on this host")
        return link

    def test_independent_export_rejects_staged_symlink(self):
        def bad_html(_data, staging):
            return self.link(staging)

        result = report_batch.publish_reports(
            self.data, self.folder, self.targets, formats=("html",),
            html_export=bad_html, pdf_export=lambda *_: None,
            machine_export=lambda *_args, **_kw: None,
        )
        self.assertIn("html", result.failed)
        self.assertEqual(result.created, {})
        self.assertFalse(self.targets["html"].exists())
        self.assertEqual(self.outside.read_text(encoding="utf-8"),
                         "never move or expose this file")
        self.assertEqual(report_batch.publication_state(self.folder, 7)["status"],
                         "partial")

    def test_pair_export_rejects_renderer_file_outside_staging(self):
        # Existing file outside TemporaryDirectory must never be moved by
        # os.replace into the final report destination.
        with patch.object(report_management, "get_session", return_value=self.data), \
             patch.object(report_management, "add_saved_comparison",
                          side_effect=lambda data: data), \
             patch.object(report_management, "export_html",
                          return_value=str(self.outside)):
            with self.assertRaisesRegex(OSError, "inside staging"):
                report_management.generate_session_reports(7, directory=self.folder)
        self.assertTrue(self.outside.exists())
        self.assertEqual(self.outside.read_text(encoding="utf-8"),
                         "never move or expose this file")
        self.assertFalse(self.targets["html"].exists())
        self.assertEqual(report_batch.publication_state(self.folder, 7)["status"],
                         "partial")

    def test_pair_export_rejects_staged_symlink(self):
        with patch.object(report_management, "get_session", return_value=self.data), \
             patch.object(report_management, "add_saved_comparison",
                          side_effect=lambda data: data), \
             patch.object(report_management, "export_html",
                          side_effect=lambda _data, staging: self.link(staging)):
            with self.assertRaisesRegex(OSError, "inside staging"):
                report_management.generate_session_reports(7, directory=self.folder)
        self.assertFalse(self.targets["html"].is_symlink())
        self.assertEqual(self.outside.read_text(encoding="utf-8"),
                         "never move or expose this file")

    def test_machine_export_rejects_outside_path_or_symlink(self):
        for output in ("outside", "symlink"):
            with self.subTest(output=output):
                def wrong_machine(_data, _folder, *, fmt):
                    if output == "outside":
                        return self.outside
                    link = self.folder / "machine.json"
                    try:
                        link.symlink_to(self.outside)
                    except (OSError, NotImplementedError):
                        self.skipTest("File symlinks unavailable on this host")
                    return link

                outcome = report_batch.publish_reports(
                    self.data, self.folder, self.targets, formats=("json",),
                    machine_export=wrong_machine,
                    html_export=lambda *_: None, pdf_export=lambda *_: None,
                )
                self.assertIn("json", outcome.failed)
                self.assertEqual(outcome.created, {})
                self.assertEqual(self.outside.read_text(encoding="utf-8"),
                                 "never move or expose this file")
                (self.folder / "machine.json").unlink(missing_ok=True)

    def test_symlinked_publication_manifest_is_ignored(self):
        import json

        self.outside.write_text(
            json.dumps({"status": "in_progress", "session": 7}),
            encoding="utf-8",
        )
        manifest = report_batch._manifest_path(self.folder, 7)
        try:
            manifest.symlink_to(self.outside)
        except (OSError, NotImplementedError):
            self.skipTest("File symlinks unavailable on this host")
        self.assertIsNone(report_batch.publication_state(self.folder, 7))
        self.assertFalse(report_batch.interrupted_publication(self.folder, 7))


if __name__ == "__main__":
    unittest.main()
