"""Regression tests for issues #86 (assessment normalization) and #87 (tuple UI)."""
import io
from contextlib import redirect_stdout
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from penx_app.storage import db
from penx_app.storage import db_backend
import penx


class AssessmentStorageTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.engine = patch.object(db_backend, "DB_ENGINE", "sqlite")
        self.path = patch.object(db_backend, "DB_PATH",
                                 str(Path(self.folder.name) / "penx_app.storage.db.sqlite"))
        self.engine.start()
        self.path.start()
        self.addCleanup(self.engine.stop)
        self.addCleanup(self.path.stop)

    def test_sparse_result_saves_conservative_unknown_risk(self):
        sid = db.create_session("example.test", status="pending")
        sparse = {
            "vulnerabilities": [{
                "vuln_name": "Service observed", "port": "443",
                "description": "Observational only",
            }]
        }
        counts = db.save_assessment(sid, sparse)
        self.assertEqual(counts["vulnerabilities"], 1)
        self.assertEqual(counts["exploits"], 0)
        self.assertEqual(sparse["risk_level"], "UNKNOWN")
        saved = db.get_session(sid)
        self.assertEqual(saved["history"][3], "active")
        self.assertEqual(saved["summary"][2:5], ("", "", "UNKNOWN"))
        self.assertEqual(saved["vulns"][0][3:7],
                         ("unknown", "possible", "443", ""))

    def test_sparsest_result_is_saved_without_invented_findings(self):
        sid = db.create_session("example.test", status="pending")
        counts = db.save_assessment(sid, {})
        self.assertEqual(counts["vulnerabilities"], 0)
        self.assertEqual(db.get_session(sid)["summary"][4], "UNKNOWN")

    def test_sparse_exploit_records_and_empty_lists(self):
        sid = db.create_session("example.test", status="pending")
        counts = db.save_assessment(sid, {"risk_level": " low ",
                                          "exploits": [{"exploit_name": "Manual review"}],
                                          "raw_scan": "Scanner: test"})
        self.assertEqual(counts["exploits"], 1)
        self.assertEqual(db.get_session(sid)["summary"][4], "LOW")

    def test_invalid_shape_and_unknown_enum_fail_before_commit(self):
        for item in ({"vulnerabilities": "not a list"},
                     {"risk_level": "SAFE"},
                     {"vulnerabilities": [{"vuln_name": ""}]}):
            sid = db.create_session("example.test", status="pending")
            with self.assertRaises(ValueError):
                db.save_assessment(sid, item)
            data = db.get_session(sid)
            self.assertEqual(data["history"][3], "pending")
            self.assertIsNone(data["summary"])
            self.assertEqual(data["vulns"], [])

    def test_invalid_correction_raises_without_database_write(self):
        sid = db.create_session("example.test")
        vid = db.save_vulnerability(sid, "Fixture", "high", "443", "https", "Original")
        with self.assertRaisesRegex(ValueError, "Invalid status"):
            db.save_correction(sid, vid, "not-a-status", "", "", "")
        self.assertEqual(db.get_corrections(sid), [])


class EditMenuTests(unittest.TestCase):
    ROW = (42, 3, "Example finding", "high", "possible",
           "443", "https", "Correct scanner description")

    def test_vulnerability_picker_uses_confidence_port_and_service(self):
        text = penx.format_vulnerability_picker(self.ROW)
        self.assertIn("Confidence: possible", text)
        self.assertIn("Port: 443", text)
        self.assertIn("Service: https", text)
        self.assertNotIn("port possible", text)

    def test_both_picker_views_use_same_formatter(self):
        for which in ("1", "8"):
            answers = iter([which, "invalid", "12"])
            with patch.object(penx, "prompt", side_effect=lambda *a, **kw: next(answers)), \
                 patch.object(penx, "get_vulnerabilities", return_value=[self.ROW]), \
                 patch.object(penx, "divider"), patch.object(penx, "show_back"), \
                 patch.object(penx, "is_back", return_value=False), \
                 redirect_stdout(io.StringIO()) as out:
                penx.edit_delete_menu(3)
            self.assertIn("Port: 443 | Service: https", out.getvalue())
            self.assertNotIn("port possible", out.getvalue())

    def test_correction_original_uses_description_not_service(self):
        answers = iter(["8", "42", "verified", "fixed", "real evidence", "12"])
        with patch.object(penx, "prompt", side_effect=lambda *a, **kw: next(answers)), \
             patch.object(penx, "get_vulnerabilities", return_value=[self.ROW]), \
             patch.object(penx, "save_correction") as save, \
             patch.object(penx, "divider"), patch.object(penx, "show_back"), \
             patch.object(penx, "is_back", return_value=False), \
             redirect_stdout(io.StringIO()):
            penx.edit_delete_menu(3)
        self.assertEqual(save.call_args.args[3],
                         "[high] Example finding: Correct scanner description")

    def test_unknown_risk_level_accepted(self):
        answers = iter(["4", "unknown", "12"])
        with patch.object(penx, "prompt", side_effect=lambda *a, **kw: next(answers)), \
             patch.object(penx, "edit_summary_risk", return_value=True) as edit, \
             patch.object(penx, "divider"), patch.object(penx, "show_back"), \
             patch.object(penx, "is_back", return_value=False), \
             redirect_stdout(io.StringIO()):
            penx.edit_delete_menu(3)
        edit.assert_called_once_with(3, "UNKNOWN")


if __name__ == "__main__":
    unittest.main(verbosity=2)
