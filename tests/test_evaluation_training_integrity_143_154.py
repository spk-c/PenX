"""Data-integrity regressions for selected reviewed training/evaluator imports."""
from __future__ import annotations

import json
import sqlite3
from contextlib import closing
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, Mock

from penx_app.storage import db, db_evals, db_training
from penx_app.storage.db_backend import SQLiteConnection
from penx_app.storage.schema_migrations import initialize_sqlite
from penx_app.domain.evaluation_parser import parse_distilled_rules
from penx_app import updates


class IntegrityRegressions(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="penx-training-integrity-")
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "fixture.sqlite"
        with closing(sqlite3.connect(self.path)) as conn:
            initialize_sqlite(conn)
            conn.execute("INSERT INTO history (sl_no, target, scan_date, status) "
                         "VALUES (1, 'example.test', 'today', 'active')")
            conn.execute("INSERT INTO history (sl_no, target, scan_date, status) "
                         "VALUES (2, 'elsewhere.test', 'today', 'active')")
            conn.execute("INSERT INTO summary "
                         "(sl_no, raw_scan, ai_analysis, risk_level, model_name, generated_at) "
                         "VALUES (1, 'synthetic scan', 'model', 'LOW', 'fixture', 'today')")
            for row in (
                (11, 1, "verified host", "high", "confirmed", "443", "https", "observed"),
                (12, 1, "unreviewed claim", "critical", "possible", "80", "http", "speculation"),
                (13, 1, "recommendation", "info", "recommendation", "", "", "tune config"),
                (14, 2, "other session", "low", "possible", "", "", "other"),
            ):
                conn.execute("INSERT INTO vulnerabilities "
                             "(id, sl_no, vuln_name, severity, confidence, port, service, description) "
                             "VALUES (?, ?, ?, ?, ?, ?, ?, ?)", row)
            conn.execute("INSERT INTO corrections "
                         "(sl_no, vuln_id, status, original_text, corrected_text, reason, corrected_at) "
                         "VALUES (1, 11, 'verified', 'orig', '', 'reviewed', 'today')")
            conn.execute("INSERT INTO corrections "
                         "(sl_no, vuln_id, status, original_text, corrected_text, reason, corrected_at) "
                         "VALUES (1, 13, 'verified', 'orig', '', 'reviewed', 'today')")
            conn.commit()

    def factory(self):
        return SQLiteConnection(sqlite3.connect(self.path))

    def test_training_excludes_unreviewed_and_recommendations_and_preserves_confidence(self):
        with patch.object(db_training, "get_connection", side_effect=self.factory):
            path = db_training.export_training_data(self.tmp.name)
        pair = json.loads(Path(path).read_text(encoding="utf-8").splitlines()[0])
        answer = pair["messages"][1]["content"]
        self.assertIn("VULN: verified host", answer)
        self.assertIn("CONFIDENCE: confirmed", answer)
        self.assertNotIn("unreviewed claim", answer)
        self.assertNotIn("VULN: recommendation", answer)
        self.assertEqual(pair["metadata"]["partial_review"], True)
        self.assertIn("RISK_LEVEL: UNKNOWN", answer)

    def test_child_writes_reject_cross_session_vulnerability(self):
        with patch.object(db, "get_connection", side_effect=self.factory):
            with self.assertRaisesRegex(ValueError, "does not belong"):
                db.save_fix(1, 14, "injected fix")
            with self.assertRaisesRegex(ValueError, "does not belong"):
                db.save_correction(1, 14, "verified", "", "", "")
        with patch.object(db_evals, "get_connection", side_effect=self.factory):
            with self.assertRaisesRegex(ValueError, "does not belong"):
                db_evals.save_evaluation(1, 14, "external", "evidence",
                                         "valid", "high", True, True, True, True, "")
        with closing(sqlite3.connect(self.path)) as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM fixes").fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM evaluations").fetchone()[0], 0)

    def test_evaluator_rejects_missing_flags_and_ignores_identical_retry(self):
        fields = ("EVAL: verified host\nVERDICT: valid\nCONFIDENCE: high\n"
                  "EVIDENCE: scanner line\nNOTES: reviewed\n")
        with patch.object(db_evals, "get_connection", side_effect=self.factory):
            self.assertEqual(db_evals.parse_evaluation_response(1, "fixture", fields), [])
            reviewed = fields + ("SEVERITY_CORRECT: yes\nCVE_CORRECT: no\n"
                                 "SOFTWARE_CORRECT: yes\nFIX_CORRECT: no\n")
            first = db_evals.parse_evaluation_response(1, "fixture", reviewed)
            second = db_evals.parse_evaluation_response(1, "fixture", reviewed)
            later = db_evals.parse_evaluation_response(1, "fixture", reviewed.replace(
                "NOTES: reviewed", "NOTES: re-reviewed"))
        self.assertEqual(len(first), 1)
        self.assertEqual(second, [])
        self.assertEqual(len(later), 1)
        with closing(sqlite3.connect(self.path)) as conn:
            records = conn.execute("SELECT severity_correct, cve_correct FROM evaluations").fetchall()
            self.assertEqual(records, [(1, 0), (1, 0)])

    def test_distillation_bounds_are_checked_before_storage(self):
        with self.assertRaisesRegex(ValueError, "128 KiB"):
            parse_distilled_rules("RULE: " + "a" * 150000)
        with self.assertRaisesRegex(ValueError, "1000 characters"):
            parse_distilled_rules("RULE: " + "a" * 1001)
        with self.assertRaisesRegex(ValueError, "100 unique"):
            parse_distilled_rules("\n".join("RULE: Verified rule number " + str(i)
                                           for i in range(101)))
        with patch.object(db_evals, "get_connection", side_effect=AssertionError("DB touched")):
            with self.assertRaises(ValueError):
                db_evals.import_distilled_rules("fixture", "RULE: " + "z" * 150000)

    def test_failed_startup_update_lookup_does_not_throttle_retry(self):
        with tempfile.TemporaryDirectory() as folder, \
             patch.object(updates, "APP_ROOT", Path(folder)), \
             patch.object(updates, "installed_mode", return_value=True), \
             patch.object(updates, "fetch_latest", side_effect=[
                 OSError("offline"), Mock(tag="v0.4.6", page_url="https://github.com/SLP-DEV1/PenX")
             ]) as fetch, \
             patch.object(updates, "is_newer", return_value=False):
            marker = Path(folder) / "data" / ".last-update-check"
            updates.startup_notice()
            self.assertFalse(marker.exists())
            updates.startup_notice()
            self.assertTrue(marker.exists())
            self.assertEqual(fetch.call_count, 2)


if __name__ == "__main__":
    unittest.main()
