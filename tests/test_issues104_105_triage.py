"""Offline regressions for PenX issues #104 and #105 and bot triage."""
from __future__ import annotations

from contextlib import redirect_stdout
from io import StringIO
import os
from pathlib import Path
import unittest
from unittest.mock import patch

import penx
from scripts import issue_triage as triage


class VulnerabilityDeletePickerTests(unittest.TestCase):
    def test_delete_menu_shows_confidence_port_service(self):
        row = (7, 21, "Shared severity", "HIGH", "possible", 443, "https", "details")
        output = StringIO()
        with patch("penx.get_vulnerabilities", return_value=[row]), \
             patch("penx.prompt", side_effect=["5", "7", "12"]), \
             patch("penx.confirm", return_value=False), \
             redirect_stdout(output):
            penx.edit_delete_menu(21)
        listing = output.getvalue()
        self.assertIn("id=7 | Shared severity | HIGH", listing)
        self.assertIn("Confidence: possible", listing)
        self.assertIn("Port: 443", listing)
        self.assertIn("Service: https", listing)

    def test_related_issue_reference_cannot_force_high_duplicate_score(self):
        reported = {
            "number": 104, "title": "Delete vulnerability picker missing fields",
            "body": "src/penx_app/cli/app.py edit_delete_menu() references #87; "
                    "get_vulnerabilities() and format_vulnerability_picker()",
        }
        previous = {
            "number": 87,
            "title": "Edit vulnerability and correction picker missing fields",
            "body": "src/penx_app/cli/app.py edit_delete_menu() "
                    "get_vulnerabilities() and format_vulnerability_picker()",
        }
        candidates = triage.duplicates(reported, [previous])
        self.assertEqual(candidates[0]["number"], 87)
        self.assertTrue(candidates[0]["explicitly_related"])
        self.assertLess(candidates[0]["score"], 0.90)

    def test_duplicate_verdict_requires_same_behavior_confirmation(self):
        candidates = [{"number": 87, "score": 0.92}]
        review = {
            "category": "bug", "verdict": "possible-duplicate",
            "duplicate_issue": 87, "duplicate_relation": "related-distinct",
            "evidence": [],
        }
        self.assertEqual(triage.validate(review, candidates, {})["verdict"],
                         "unverified")
        review["duplicate_relation"] = "same-behavior"
        self.assertEqual(triage.validate(review, candidates, {})["verdict"],
                         "possible-duplicate")

    def test_similar_title_does_not_skip_configured_ai(self):
        issue = {"number": 104, "title": "Delete picker missing port",
                 "body": "src/penx_app/cli/app.py edit_delete_menu() in delete choice"}
        previous = {"number": 87, "title": issue["title"],
                    "body": "src/penx_app/cli/app.py edit_delete_menu() in edit choice",
                    "state": "closed"}
        with patch.dict(os.environ, {"PENX_TRIAGE_GROQ_API_KEY": "mock-key"}), \
             patch.object(triage, "request_json", side_effect=[issue, [previous]]), \
             patch.object(triage, "model_review", return_value={
                 "category": "bug", "verdict": "unverified",
                 "summary": "Different menu branch", "duplicate_issue": None,
             }) as model:
            result = triage.review("SLP-DEV1/PenX", 104, "mock-token",
                                  Path(__file__).resolve().parents[1])
        model.assert_called_once()
        self.assertIn("edit choice", model.call_args.args[1][0]["body_excerpt"])
        self.assertEqual(result["verdict"], "unverified")


class ScanDiagnosticIntentTests(unittest.TestCase):
    def _failed_scan(self, error=None, *, usable=True):
        with patch("penx.prompt", return_value="example.test"), \
             patch("penx.llm_auth_preflight", return_value=True), \
             patch("penx.get_all_history", return_value=[]), \
             patch("penx.interactive_tool_run",
                   side_effect=error, return_value="diagnostics only"), \
             patch("penx.recon_has_evidence", return_value=usable), \
             patch("penx.create_session",
                   side_effect=AssertionError("Unexpected DB write")):
            outcome = penx._execute_scan()
        self.assertFalse(outcome.completed)
        self.assertTrue(outcome.acknowledge,
                        "Failure diagnostics must remain visible until acknowledged")
        return outcome

    def test_interrupted_or_failed_scans_retain_diagnostics(self):
        for failure in (KeyboardInterrupt(), RuntimeError("offline failure")):
            with self.subTest(failure=type(failure).__name__):
                outcome = self._failed_scan(error=failure)
                self.assertIn(outcome.stage, ("interrupted", "recon_failed"))

    def test_no_evidence_acknowledged_but_new_cancel_does_not_inherit_state(self):
        self.assertEqual(self._failed_scan(usable=False).stage, "no_evidence")
        with patch("penx.prompt", return_value="back"):
            outcome = penx._execute_scan()
            self.assertIs(penx.new_scan(), False)
        self.assertFalse(outcome.acknowledge)
        self.assertEqual(outcome.stage, "cancelled")
        self.assertFalse(hasattr(penx, "_SCAN_DIAGNOSTIC_PENDING"))

    def test_terminal_consumes_explicit_outcome_without_module_flag(self):
        from penx_app.application.scan_outcome import ScanOutcome
        root = Path(__file__).resolve().parents[1]
        excerpts, indexed = triage.code_context(root, {
            "title": "New scan diagnostics require acknowledgement",
            "body": "Check src/penx_app/cli/app.py _execute_scan() "
                    "and _main_menu_loop() for ScanOutcome behavior.",
        })
        self.assertIn("if outcome.acknowledge:", excerpts)
        self.assertTrue(any(
            line.strip() == "if outcome.acknowledge:"
            for line in indexed["src/penx_app/cli/app.py"].values()
        ))
        self.assertTrue(ScanOutcome(False, True, "recon_failed").acknowledge)
        with self.assertRaises(ValueError):
            ScanOutcome(True, False, "completed")

    def test_long_triage_message_keeps_complete_footer(self):
        result = {
            "verdict": "likely-valid", "summary": "Long review",
            "reason": "Example detail. " * 100,
            "impact": "Long impact. " * 50,
            "verification": "source-inspection-only",
            "evidence": [{"file": "src/penx_app/cli/app.py", "line": i} for i in range(1, 18)],
            "findings": [], "missing": [], "duplicate_issue": None,
            "next_step": "Run an offline regression test.",
        }
        text = triage.comment("SLP-DEV1/PenX", result)
        self.assertLessEqual(len(text), 3500)
        self.assertTrue(text.endswith(
            "Only a maintainer can confirm the bug or close this issue._"))


if __name__ == "__main__":
    unittest.main()
