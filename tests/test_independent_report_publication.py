"""Independent per-format publication preserves successful and earlier files."""
from pathlib import Path
import tempfile
import unittest

from penx_app.reporting.report_batch import publish_reports


class ReportBatchContracts(unittest.TestCase):
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
    def html(data, folder):
        path = Path(folder) / "rendered.html"
        path.write_text("new HTML", encoding="utf-8")
        return str(path)

    @staticmethod
    def failing_pdf(data, folder):
        raise OSError("PDF renderer failed")

    def test_failed_pdf_preserves_existing_pdf_and_successful_new_html(self):
        self.paths["pdf"].write_bytes(b"prior PDF")
        result = publish_reports(
            self.data, self.folder, self.paths,
            html_export=self.html, pdf_export=self.failing_pdf,
            machine_export=lambda *args, **kwargs: None,
        )
        self.assertFalse(result.complete)
        self.assertEqual(result.created, {"html": self.paths["html"]})
        self.assertIn("PDF renderer failed", result.failed["pdf"])
        self.assertEqual(self.paths["html"].read_text(), "new HTML")
        self.assertEqual(self.paths["pdf"].read_bytes(), b"prior PDF")

    def test_json_sarif_continue_after_pdf_failure(self):
        seen = []
        def machine(data, folder, *, fmt):
            seen.append(fmt)
            path = Path(folder) / f"report.{fmt}"
            path.write_text(fmt, encoding="utf-8")
            return path
        outcome = publish_reports(
            self.data, self.folder, self.paths,
            formats=("html", "pdf", "json", "sarif"),
            html_export=self.html, pdf_export=self.failing_pdf,
            machine_export=machine,
        )
        self.assertEqual(set(outcome.created), {"html", "json", "sarif"})
        self.assertEqual(seen, ["json", "sarif"])
        self.assertEqual(list(self.folder.glob(".penx-format-*")), [])

    def test_missing_session_and_invalid_format_fail_closed(self):
        with self.assertRaises(ValueError):
            publish_reports({"history": None}, self.folder, self.paths)
        with self.assertRaises(ValueError):
            publish_reports(self.data, self.folder, self.paths, formats=("exe",))

    def test_symlink_is_not_followed(self):
        outside = self.folder / "untouched.html"
        outside.write_text("safe", encoding="utf-8")
        try:
            self.paths["html"].symlink_to(outside)
        except (OSError, NotImplementedError):
            self.skipTest("No symlink privileges")
        outcome = publish_reports(
            self.data, self.folder, self.paths, formats=("html",),
            html_export=self.html, pdf_export=self.failing_pdf,
            machine_export=lambda *args, **kwargs: None,
        )
        self.assertIn("html", outcome.failed)
        self.assertEqual(outside.read_text(), "safe")


if __name__ == "__main__":
    unittest.main()
