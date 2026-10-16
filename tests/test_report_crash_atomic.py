"""Crash-detectable multi-file report publication.

Every multi-format batch is bracketed by an atomic per-session manifest
(``report_batch``). These tests prove that a process crash *mid-batch* leaves
a detectable ``in_progress`` state and that re-running the same publication
recovers it, without changing report filenames or formats.
"""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

_STORE = tempfile.TemporaryDirectory(prefix="penx_report_crash_")
os.environ["PENX_DB_ENGINE"] = "sqlite"
os.environ["PENX_DB_PATH"] = str(Path(_STORE.name) / "database.sqlite")

from penx_app.reporting import report_batch
from penx_app.reporting import report_management as reports
from penx_app.storage import db


class _Crash(BaseException):
    """Simulates a hard process crash that ``except Exception`` cannot catch."""


def _empty_assessment():
    return {
        "vulnerabilities": [],
        "recommendations": [],
        "exploits": [],
        "raw_scan": "80/tcp open http\nNmap done:",
        "full_response": "RISK_LEVEL: LOW\nSUMMARY: No confirmed vulnerabilities.",
        "risk_level": "LOW",
    }


class ManifestContractTests(unittest.TestCase):
    """Pure manifest helpers (no DB, no renderers)."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)

    def test_begin_writes_in_progress_hidden_manifest(self):
        path = report_batch.begin_publication(self.folder, 7, ("html", "pdf"))
        self.assertTrue(path.is_file())
        self.assertTrue(path.name.startswith(".penx-publication_SL"))
        state = report_batch.publication_state(self.folder, 7)
        self.assertEqual(state["status"], "in_progress")
        self.assertEqual(state["formats"], ["html", "pdf"])
        self.assertTrue(report_batch.interrupted_publication(self.folder, 7))

    def test_finalize_complete_and_no_longer_interrupted(self):
        report_batch.begin_publication(self.folder, 7, ("html", "pdf"))
        report_batch.finalize_publication(
            self.folder, 7, {"html": self.folder / "a.html"}, {})
        state = report_batch.publication_state(self.folder, 7)
        self.assertEqual(state["status"], "complete")
        self.assertIn("a.html", state["created"]["html"])
        self.assertFalse(report_batch.interrupted_publication(self.folder, 7))

    def test_finalize_partial_records_failed_format_but_is_not_interrupted(self):
        report_batch.begin_publication(self.folder, 9, ("html", "pdf"))
        report_batch.finalize_publication(
            self.folder, 9, {"html": self.folder / "a.html"},
            {"pdf": "OSError: disk full"})
        state = report_batch.publication_state(self.folder, 9)
        self.assertEqual(state["status"], "partial")
        self.assertEqual(state["failed"], {"pdf": "OSError: disk full"})
        # A partial batch ran to completion; it is not an interrupted crash.
        self.assertFalse(report_batch.interrupted_publication(self.folder, 9))

    def test_missing_or_corrupt_manifest_is_not_interrupted(self):
        self.assertIsNone(report_batch.publication_state(self.folder, 3))
        self.assertFalse(report_batch.interrupted_publication(self.folder, 3))
        (self.folder / ".penx-publication_SL3.json").write_text(
            "{not json", encoding="utf-8")
        self.assertIsNone(report_batch.publication_state(self.folder, 3))
        self.assertFalse(report_batch.interrupted_publication(self.folder, 3))


class PublishReportsCrashTests(unittest.TestCase):
    """``publish_reports``: a mid-batch crash leaves a recoverable manifest."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.paths = {
            "html": self.folder / "penx_SL1_fixture.html",
            "pdf": self.folder / "penx_SL1_fixture.pdf",
        }
        self.data = {
            "history": (1, "fixture.test", "today", "active"),
            "summary": (1, 1, "raw", "model", "LOW", "local", "today"),
            "vulns": [], "fixes": [], "corrections": [],
        }

    @staticmethod
    def _render_html(data, folder):
        path = Path(folder) / "rendered.html"
        path.write_text("new HTML", encoding="utf-8")
        return str(path)

    @staticmethod
    def _render_pdf(data, folder):
        path = Path(folder) / "rendered.pdf"
        path.write_bytes(b"%PDF-1.4 test")
        return str(path)

    @staticmethod
    def _crash_pdf(data, folder):
        raise _Crash("process crashed during PDF export")

    def test_success_finalizes_complete_manifest(self):
        outcome = report_batch.publish_reports(
            self.data, self.folder, self.paths,
            html_export=self._render_html, pdf_export=self._render_pdf,
            machine_export=lambda *args, **kwargs: None,
        )
        self.assertEqual(set(outcome.created), {"html", "pdf"})
        state = report_batch.publication_state(self.folder, 1)
        self.assertEqual(state["status"], "complete")
        self.assertFalse(report_batch.interrupted_publication(self.folder, 1))
        self.assertIn("html", state["created"])
        self.assertIn("pdf", state["created"])

    def test_crash_mid_batch_leaves_detectable_recoverable_state(self):
        # html publishes first, then the process "crashes" during pdf. A
        # BaseException escapes ``publish_reports``' ``except Exception`` so the
        # manifest is never finalized, exactly like a real crash.
        with self.assertRaises(_Crash):
            report_batch.publish_reports(
                self.data, self.folder, self.paths,
                html_export=self._render_html, pdf_export=self._crash_pdf,
                machine_export=lambda *args, **kwargs: None,
            )
        self.assertTrue(report_batch.interrupted_publication(self.folder, 1))
        # The format published before the crash survives intact.
        self.assertTrue(self.paths["html"].is_file())
        self.assertFalse(self.paths["pdf"].is_file())
        # Recovery: re-running the same publication completes the batch.
        outcome = report_batch.publish_reports(
            self.data, self.folder, self.paths,
            html_export=self._render_html, pdf_export=self._render_pdf,
            machine_export=lambda *args, **kwargs: None,
        )
        self.assertEqual(set(outcome.created), {"html", "pdf"})
        self.assertFalse(report_batch.interrupted_publication(self.folder, 1))
        self.assertEqual(
            report_batch.publication_state(self.folder, 1)["status"], "complete")
        self.assertTrue(self.paths["pdf"].is_file())

    def test_no_temp_report_dirs_left_behind_after_crash(self):
        with self.assertRaises(_Crash):
            report_batch.publish_reports(
                self.data, self.folder, self.paths,
                html_export=self._render_html, pdf_export=self._crash_pdf,
                machine_export=lambda *args, **kwargs: None,
            )
        self.assertEqual(list(self.folder.glob(".penx-format-*")), [])


class GenerateSessionCrashTests(unittest.TestCase):
    """``generate_session_reports`` (HTML+PDF pair) is also crash-atomic."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="penx_report_crash_mgmt_")
        self.root = Path(self.tmp.name)
        self.root_patch = patch.object(reports, "APP_ROOT", self.root)
        self.root_patch.start()
        self.sessions = []

    def tearDown(self):
        for sl in self.sessions:
            if db.get_session(sl)["history"]:
                db.delete_full_session(sl)
        self.root_patch.stop()
        self.tmp.cleanup()

    def _make_session(self, target="shop.example.test"):
        sl = db.create_session(target, status="pending")
        self.sessions.append(sl)
        db.save_assessment(sl, _empty_assessment(), model_name="test")
        return sl

    def test_success_finalizes_complete_manifest(self):
        sl = self._make_session("shop.example.test")
        paths = reports.generate_session_reports(sl)
        folder = paths["html"].parent
        state = report_batch.publication_state(folder, sl)
        self.assertEqual(state["status"], "complete")
        self.assertFalse(report_batch.interrupted_publication(folder, sl))

    def test_render_io_error_is_partial_not_a_crash(self):
        sl = self._make_session("error.example.test")
        with patch.object(reports, "export_pdf", side_effect=OSError("disk full")):
            with self.assertRaisesRegex(OSError, "disk full"):
                reports.generate_session_reports(sl)
        folder = reports.report_paths(sl, "error.example.test")["html"].parent
        state = report_batch.publication_state(folder, sl)
        self.assertEqual(state["status"], "partial")
        self.assertIn("disk full", state["failed"]["batch"])
        self.assertFalse(report_batch.interrupted_publication(folder, sl))

    def test_delete_reports_removes_manifest_containing_report_paths(self):
        sl = self._make_session("private.example.test")
        paths = reports.generate_session_reports(sl)
        folder = paths["html"].parent
        manifest = folder / f".penx-publication_SL{sl}.json"
        self.assertTrue(manifest.is_file())
        self.assertIn("private_example_test", manifest.read_text(encoding="utf-8"))
        removed = reports.delete_session_reports(sl, "private.example.test")
        self.assertEqual(set(removed), set(paths.values()))
        self.assertFalse(manifest.exists())

    def test_render_crash_leaves_interrupted_state_then_recover(self):
        sl = self._make_session("shop.example.test")
        with patch.object(reports, "export_pdf", side_effect=_Crash("crash")):
            with self.assertRaises(_Crash):
                reports.generate_session_reports(sl)
        folder = reports.report_paths(sl, "shop.example.test")["html"].parent
        self.assertTrue(report_batch.interrupted_publication(folder, sl))
        # Recovery: re-running completes the batch and both files exist.
        paths = reports.generate_session_reports(sl)
        self.assertFalse(report_batch.interrupted_publication(folder, sl))
        self.assertEqual(
            report_batch.publication_state(folder, sl)["status"], "complete")
        self.assertTrue(paths["html"].is_file())
        self.assertTrue(paths["pdf"].is_file())


if __name__ == "__main__":
    unittest.main()
