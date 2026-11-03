"""Offline regression: planning and roadmap issues must not get bug triage."""

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import os
import sys

from scripts import issue_triage as triage


class PlanningIssueTriageTests(unittest.TestCase):
    def test_title_and_label_recognition(self):
        planning = [
            {"title": "Roadmap: PenX v0.7-v1.0"},
            {"title": "[Roadmap] Reliability"},
            {"title": "Milestone - Version 1"},
            {"title": "[Epic] Workspace"},
            {"title": "Status report", "labels": [{"name": "roadmap"}]},
            {"title": "Tasks", "labels": ["type:planning"]},
        ]
        for issue in planning:
            with self.subTest(issue=issue):
                self.assertTrue(triage.is_planning_issue(issue))
        normal = [
            {"title": "Roadmap button crashes when clicked"},
            {"title": "Feature request: new scanner"},
            {"title": "Installer bug and failed restore"},
            {"title": "Roadmap section has a typo"},
        ]
        for issue in normal:
            with self.subTest(issue=issue):
                self.assertFalse(triage.is_planning_issue(issue))

    def test_review_skips_tracker_before_duplicate_or_model_queries(self):
        issue = {"number": 123, "title": "Roadmap: PenX v0.7-v1.0",
                 "body": "Tracking milestones"}
        with patch.object(triage, "request_json", return_value=issue) as api:
            with patch.object(triage, "model_review") as model:
                outcome = triage.review("spk-c/PenX", 123, "fake", Path("."))
        self.assertIsNone(outcome)
        model.assert_not_called()
        api.assert_called_once()

    def test_no_report_means_no_publisher_job(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "github_output"
            with patch.dict(os.environ, {"GITHUB_TOKEN": "fake", "GITHUB_OUTPUT": str(output),
                                          "GITHUB_EVENT_NAME": "issues"}):
                with patch.object(sys, "argv", ["issue_triage.py", "review"]):
                    with patch.object(triage, "repository", return_value="spk-c/PenX"):
                        with patch.object(triage, "issue_number", return_value=123):
                            with patch.object(triage, "review", return_value=None):
                                self.assertEqual(triage.main(), 0)
            self.assertEqual(output.read_text(encoding="utf-8"),
                             "report=\nissue_number=\n")

    def test_bug_reports_still_follow_normal_review_pipeline(self):
        normal = {"number": 20, "title": "Nmap parser crashes", "body": "Repro steps"}
        with patch.object(triage, "request_json", side_effect=[normal, []]) as api:
            with patch.dict(os.environ, {"PENX_TRIAGE_GROQ_API_KEY": ""}):
                outcome = triage.review("spk-c/PenX", 20, "fake", Path("."))
        self.assertIsInstance(outcome, dict)
        self.assertIn("comment", outcome)
        self.assertGreater(api.call_count, 1)


if __name__ == "__main__":
    unittest.main()
