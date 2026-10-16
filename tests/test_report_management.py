"""Offline regressions for automatic HTML/PDF exports and history report cleanup."""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

_STORE = tempfile.TemporaryDirectory(prefix="penx_reports_test_")
os.environ["PENX_DB_ENGINE"] = "sqlite"
os.environ["PENX_DB_PATH"] = str(Path(_STORE.name) / "database.sqlite")

from penx_app.storage import db
import penx
from penx_app.reporting import report_management as reports


def empty_assessment():
    return {
        "vulnerabilities": [],
        "recommendations": [],
        "exploits": [],
        "raw_scan": "80/tcp open http\nNmap done:",
        "full_response": "RISK_LEVEL: LOW\nSUMMARY: No confirmed vulnerabilities.",
        "risk_level": "LOW",
    }


class ReportWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="penx_export_test_")
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

    def make_session(self, target="example.test", *, complete=True):
        sl = db.create_session(target, status="pending")
        self.sessions.append(sl)
        if complete:
            db.save_assessment(sl, empty_assessment(), model_name="test")
        return sl

    def test_complete_session_generates_both_formats_and_correct_name(self):
        sl = self.make_session("shop.example.test")
        paths = reports.generate_session_reports(sl)
        self.assertEqual(set(paths), {"html", "pdf"})
        self.assertEqual(paths["html"].parent, self.root / "reports")
        self.assertEqual(paths["html"].name, f"penx_SL{sl}_shop_example_test.html")
        self.assertIn("shop.example.test", paths["html"].read_text(encoding="utf-8"))
        self.assertTrue(paths["pdf"].read_bytes().startswith(b"%PDF"))
        self.assertEqual(reports.existing_reports(sl, "shop.example.test"), paths)

    def test_pending_or_missing_session_never_generates_report(self):
        sl = self.make_session(complete=False)
        with self.assertRaisesRegex(ValueError, "not a completed assessment"):
            reports.generate_session_reports(sl)
        with self.assertRaisesRegex(ValueError, "not a completed assessment"):
            reports.generate_session_reports(sl + 1000000)
        self.assertFalse((self.root / "reports").exists())

    def test_delete_only_selected_session_files_preserves_database(self):
        first = self.make_session("first.example")
        other = self.make_session("other.example")
        first_paths = reports.generate_session_reports(first)
        other_paths = reports.generate_session_reports(other)
        notes = self.root / "reports" / "important-not-a-penx-report.txt"
        notes.write_text("DO NOT DELETE", encoding="utf-8")
        removed = reports.delete_session_reports(first, "first.example")
        self.assertEqual(set(removed), set(first_paths.values()))
        self.assertEqual(reports.existing_reports(first, "first.example"), {})
        self.assertTrue(all(p.exists() for p in other_paths.values()))
        self.assertEqual(notes.read_text(encoding="utf-8"), "DO NOT DELETE")
        self.assertIsNotNone(db.get_session(first)["history"])
        self.assertEqual(reports.delete_session_reports(first, "first.example"), [])

    def test_export_failure_preserves_existing_files(self):
        sl = self.make_session()
        originals = reports.generate_session_reports(sl)
        old_bytes = {k: p.read_bytes() for k, p in originals.items()}
        with patch("penx_app.reporting.report_management.export_pdf", side_effect=OSError("disk full")):
            with self.assertRaisesRegex(OSError, "disk full"):
                reports.generate_session_reports(sl)
        for kind, path in originals.items():
            self.assertEqual(path.read_bytes(), old_bytes[kind])

    def test_second_publish_failure_restores_both_existing_files(self):
        sl = self.make_session("existing.example")
        paths = reports.generate_session_reports(sl)
        expected = {"html": b"old HTML report", "pdf": b"old PDF report"}
        for kind, previous in expected.items():
            paths[kind].write_bytes(previous)
        unrelated = self.root / "reports" / "keep-this.txt"
        unrelated.write_text("untouched", encoding="utf-8")
        original_replace = reports.os.replace

        def fail_pdf_publish(source, destination):
            if Path(destination) == paths["pdf"]:
                raise OSError("simulated PDF publish failure")
            return original_replace(source, destination)

        with patch("penx_app.reporting.report_management.os.replace", side_effect=fail_pdf_publish):
            with self.assertRaisesRegex(OSError, "simulated PDF publish failure"):
                reports.generate_session_reports(sl)

        self.assertEqual({kind: p.read_bytes() for kind, p in paths.items()}, expected)
        self.assertEqual(unrelated.read_text(encoding="utf-8"), "untouched")
        self.assertIsNotNone(db.get_session(sl)["summary"])

    def test_second_publish_failure_removes_new_html_if_no_previous_reports(self):
        sl = self.make_session("new.example")
        paths = reports.report_paths(sl, "new.example")
        original_replace = reports.os.replace

        def fail_pdf_publish(source, destination):
            if Path(destination) == paths["pdf"]:
                raise OSError("simulated PDF publish failure")
            return original_replace(source, destination)

        with patch("penx_app.reporting.report_management.os.replace", side_effect=fail_pdf_publish):
            with self.assertRaisesRegex(OSError, "simulated PDF publish failure"):
                reports.generate_session_reports(sl)

        self.assertFalse(paths["html"].exists())
        self.assertFalse(paths["pdf"].exists())
        self.assertIsNotNone(db.get_session(sl)["summary"])

    def test_directory_in_pdf_slot_prevents_partial_report_deletion(self):
        sl = self.make_session("example.test")
        paths = reports.report_paths(sl, "example.test")
        paths["html"].parent.mkdir(parents=True, exist_ok=True)
        paths["html"].write_text("keep HTML", encoding="utf-8")
        paths["pdf"].mkdir()
        with self.assertRaises(OSError):
            reports.delete_session_reports(sl, "example.test")
        self.assertEqual(paths["html"].read_text(encoding="utf-8"), "keep HTML")

    def test_manifest_symlink_prevents_deleting_other_reports(self):
        sl = self.make_session("example.test")
        paths = reports.report_paths(sl, "example.test")
        paths["html"].parent.mkdir(parents=True, exist_ok=True)
        paths["html"].write_text("keep HTML", encoding="utf-8")
        manifest = paths["html"].parent / f".penx-publication_SL{sl}.json"
        other = self.root / "private-note.txt"
        other.write_text("keep", encoding="utf-8")
        try:
            manifest.symlink_to(other)
        except (OSError, NotImplementedError):
            self.skipTest("Symlink creation unavailable on this Windows runner")
        with self.assertRaises(OSError):
            reports.delete_session_reports(sl, "example.test")
        self.assertTrue(paths["html"].is_file())
        self.assertEqual(other.read_text(encoding="utf-8"), "keep")

    def test_symlink_is_never_followed_for_report_deletion(self):
        sl = self.make_session()
        names = reports.report_paths(sl, "example.test")
        names["html"].parent.mkdir(parents=True, exist_ok=True)
        outside = self.root / "keep.html"
        outside.write_text("keep", encoding="utf-8")
        try:
            names["html"].symlink_to(outside)
        except (OSError, NotImplementedError):
            self.skipTest("Symlink creation unavailable on this Windows runner")
        with self.assertRaises(OSError):
            reports.delete_session_reports(sl, "example.test")
        self.assertTrue(outside.is_file())
        self.assertEqual(outside.read_text(encoding="utf-8"), "keep")

    def test_history_delete_reports_only_keeps_scan(self):
        sl = self.make_session("shop.example")
        paths = reports.generate_session_reports(sl)
        with patch("penx.prompt", side_effect=[str(sl), "2", "0"]), \
             patch("penx.confirm", return_value=True), \
             patch("penx.print_session"):
            penx.view_history()
        self.assertTrue(db.get_session(sl)["history"])
        self.assertFalse(any(path.exists() for path in paths.values()))

    def test_history_delete_full_scan_and_reports_requires_two_confirmations(self):
        sl = self.make_session("shop.example")
        paths = reports.generate_session_reports(sl)
        with patch("penx.prompt", side_effect=[str(sl), "4"]), \
             patch("penx.confirm", side_effect=[True, True]), \
             patch("penx.print_session"):
            penx.view_history()
        self.assertIsNone(db.get_session(sl)["history"])
        self.assertFalse(any(path.exists() for path in paths.values()))

    def test_declined_session_deletion_keeps_files(self):
        sl = self.make_session("shop.example")
        paths = reports.generate_session_reports(sl)
        with patch("penx.prompt", side_effect=[str(sl), "4", "0"]), \
             patch("penx.confirm", side_effect=[True, False]), \
             patch("penx.print_session"):
            penx.view_history()
        self.assertIsNotNone(db.get_session(sl)["history"])
        self.assertTrue(all(path.is_file() for path in paths.values()))

    def test_successful_new_scan_exports_before_display(self):
        recorded = []
        def exporter(sl):
            self.assertIsNotNone(db.get_session(sl)["summary"])
            self.assertEqual(db.get_session(sl)["history"][3], "active")
            recorded.append(sl)
            return reports.generate_session_reports(sl)

        with patch("penx.prompt", return_value="fresh.example"), \
             patch("penx.llm_auth_preflight", return_value=True), \
             patch("penx.get_all_history", return_value=[]), \
             patch("penx.interactive_tool_run", return_value="80/tcp open http\nNmap done:"), \
             patch("penx.analyse_target", return_value=empty_assessment()), \
             patch("penx.recon_has_evidence", return_value=True), \
             patch("penx.generate_session_reports", side_effect=exporter), \
             patch("penx.print_session", side_effect=RuntimeError("UI fails later")), \
             patch("penx.warn") as warning:
            self.assertIs(penx.new_scan(), True)
        self.assertTrue(any("follow-up display/review failed" in str(call)
                            for call in warning.call_args_list))
        self.assertEqual(len(recorded), 1)
        sl = recorded[0]
        self.sessions.append(sl)
        self.assertIsNotNone(db.get_session(sl)["history"])
        self.assertEqual(len(reports.existing_reports(sl, "fresh.example")), 2)

    def test_auto_export_failure_never_rolls_back_completed_scan(self):
        sessions_before = {r[0] for r in db.get_all_history()}
        with patch("penx.prompt", return_value="failed-export.example"), \
             patch("penx.llm_auth_preflight", return_value=True), \
             patch("penx.get_all_history", return_value=[]), \
             patch("penx.interactive_tool_run", return_value="80/tcp open http\nNmap done:"), \
             patch("penx.analyse_target", return_value=empty_assessment()), \
             patch("penx.recon_has_evidence", return_value=True), \
             patch("penx.generate_session_reports", side_effect=OSError("no disk space")), \
             patch("penx.print_session"), \
             patch("penx_app.application.risk_assessment.assessment_for_session", return_value=[]), \
             patch("penx_app.cli.assessment_ui.automatic_regression_check"), \
             patch("penx.confirm", return_value=False):
            penx.new_scan()
        new = {r[0] for r in db.get_all_history()} - sessions_before
        self.assertEqual(len(new), 1)
        sl = new.pop()
        self.sessions.append(sl)
        self.assertIsNotNone(db.get_session(sl)["summary"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
