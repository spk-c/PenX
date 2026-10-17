"""Risk override edits preserve independently reviewed values and session scope."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from penx_app.application.risk_assessment import (
    assess_finding, save_override, assessment_for_session,
)


def session(session_id=12):
    row = (3, session_id, "Outdated TLS cipher", "medium", "likely",
           "443", "https", "Review configuration")
    return {"history": (session_id, "example.test", "2026-10-17", "active"),
            "vulns": [row], "corrections": []}


class RiskOverridePartialUpdateTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / "data" / "risk_overrides.json"
        self.record = session()

    def test_priority_only_edit_keeps_manually_reviewed_score_and_techniques(self):
        with patch("penx_app.application.risk_assessment.get_session",
                   return_value=self.record):
            save_override(12, 3, score=88, techniques=["T1110"],
                          path=self.path)
            save_override(12, 3, priority="quick win", path=self.path)
            saved = assessment_for_session(12, path=self.path)[0]
        self.assertEqual(saved["score"], 88)
        self.assertEqual(saved["priority"], "quick win")
        self.assertEqual(saved["techniques"][0]["id"], "T1110")
        self.assertEqual(json.loads(self.path.read_text())["12:3"],
                         {"score": 88, "techniques": ["T1110"],
                          "priority": "quick win"})

    def test_score_only_edit_preserves_priority_and_existing_techniques(self):
        with patch("penx_app.application.risk_assessment.get_session",
                   return_value=self.record):
            save_override(12, 3, priority="planned",
                          techniques=["T1110"], path=self.path)
            save_override(12, 3, score=42, path=self.path)
        self.assertEqual(json.loads(self.path.read_text())["12:3"],
                         {"priority": "planned", "techniques": ["T1110"],
                          "score": 42})

    def test_invalid_update_does_not_mutate_original_file(self):
        with patch("penx_app.application.risk_assessment.get_session",
                   return_value=self.record):
            save_override(12, 3, score=50, path=self.path)
            prior = self.path.read_bytes()
            with self.assertRaisesRegex(ValueError, "Risk score override"):
                save_override(12, 3, score=101, path=self.path)
        self.assertEqual(self.path.read_bytes(), prior)

    def test_malformed_existing_override_is_rejected_without_data_loss(self):
        self.path.parent.mkdir(parents=True)
        self.path.write_text('{"12:3":"malformed"}\n', encoding="utf-8")
        before = self.path.read_bytes()
        with patch("penx_app.application.risk_assessment.get_session",
                   return_value=self.record), self.assertRaises(ValueError):
            save_override(12, 3, priority="planned", path=self.path)
        self.assertEqual(self.path.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
