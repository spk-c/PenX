"""Replay the real failure patterns seen in closed PenX bot reviews.

These tests exercise source selection and classifications without calling Groq,
opening targets, or mutating GitHub issues. Assertions check actual repository
code rather than reusing alleged source snippets supplied by issue reporters.
"""
from __future__ import annotations

import os
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch

from scripts import issue_triage as it


ROOT = Path(__file__).resolve().parents[1]


class ClosedIssueReviewerRegressions(TestCase):
    def test_issue_39_named_scan_and_rollback_are_visible(self):
        query = {
            "title": "Bug: pending sessions and inconsistent return values in new_scan()",
            "body": ("In src/penx_app/cli/app.py new_scan() can leave pending sessions on requests "
                     "errors. Inspect preserve_failed_recon(), _discard_failed_scan() "
                     "and delete_full_session() in src/penx_app/storage/db.py. How does except Exception "
                     "handle errors and return False? Is os.O_EXCL safe?"),
        }
        excerpt, evidence = it.code_context(ROOT, query)
        self.assertIn("FILE src/penx_app/cli/app.py", excerpt)
        self.assertIn("def new_scan(", excerpt)
        self.assertIn("def preserve_failed_recon(", excerpt)
        self.assertIn("FILE src/penx_app/storage/db.py", excerpt)
        self.assertIn("return False", excerpt)
        self.assertIn("except", excerpt)
        self._check_evidence(excerpt, evidence)

    def test_issue_42_cidr_and_nmap_flag_implementation_are_visible(self):
        query = {
            "title": "Invalid CIDR, overly broad scope and -Pn silently ignored",
            "body": ("src/penx_app/scanners/tools.py _host() accepts malformed CIDR 192.168.1.1/33 "
                     "and 0.0.0.0/0. Check ipaddress.ip_network, value.split('/'), "
                     "run_nmap() fixed args and run_tool_by_command() allowed_nmap "
                     "and -Pn handling. Actual vs expected. "),
        }
        excerpt, evidence = it.code_context(ROOT, query)
        self.assertEqual(list(evidence), ["src/penx_app/scanners/tools.py", "src/penx_app/scanners/scanner_targets.py"])
        for expected in ("def _host(", "ipaddress.ip_network", "def run_nmap(",
                         "def run_tool_by_command(", "allowed_nmap"):
            with self.subTest(expected=expected):
                self.assertIn(expected, excerpt)
        self._check_evidence(excerpt, evidence)

    def test_issue_44_dedup_and_missing_scanner_output_are_visible(self):
        query = {
            "title": "Bug: tool dedup, failed-recon persistence and CLI error handling",
            "body": ("In src/penx_app/analysis/llm.py analyse_target() uses key = (call_type, adapter) "
                     "and run_tool_calls() calls summarize_tool_output(output.strip()). "
                     "In src/penx_app/cli/app.py preserve_failed_recon() uses os.O_EXCL and "
                     "edit_delete_menu() accepts bad fields."),
        }
        excerpt, evidence = it.code_context(ROOT, query)
        self.assertIn("FILE src/penx_app/analysis/llm.py", excerpt)
        self.assertIn("def analyse_target(", excerpt)
        self.assertIn("def run_tool_calls(", excerpt)
        self.assertIn("key = (call_type,", excerpt)
        self.assertIn("FILE src/penx_app/cli/app.py", excerpt)
        self.assertIn("def preserve_failed_recon(", excerpt)
        self._check_evidence(excerpt, evidence)

    def test_closed_issue_46_is_flagged_as_candidate_duplicate_not_closed(self):
        old = {"number": 39, "title": "Bug: pending sessions, inconsistent return values and unsafe failure cleanup in new_scan()",
               "body": ("new_scan() catches a narrow exception set. "
                        "preserve_failed_recon() uses os.O_EXCL and cleanup "
                        "delete_full_session() can crash. The main_menu() return "
                        "and edit_delete_menu() field validation are inconsistent."),
               "state": "closed"}
        current = {"number": 46, "title": "Bug: incomplete exception handling and cleanup in new_scan()",
                   "body": ("Related: #39, #40. Extends issue #39: new_scan() exception "
                            "handling, preserve_failed_recon() collision handling, "
                            "delete_full_session() and main_menu() with wrong return values."),
                   "state": "open"}
        candidates = it.duplicates(current, [old])
        self.assertEqual(candidates[0]["number"], 39)
        self.assertTrue(candidates[0]["explicitly_related"])
        # Cross-references must not automatically increase confidence to 0.90.
        self.assertLess(candidates[0]["score"], 0.90)
        with patch.dict(os.environ, {"PENX_TRIAGE_GROQ_API_KEY": ""}), \
             patch.object(it, "request_json", side_effect=[current, [old]]), \
             patch.object(it, "model_review", side_effect=AssertionError("not configured")):
            reviewed = it.review("SLP-DEV1/PenX", 46, "fake", ROOT)
        self.assertEqual(reviewed["verdict"], "needs-info")
        self.assertIn("Related issue (not confirmed duplicate)", reviewed["comment"])
        self.assertIn("/issues/39", reviewed["comment"])

    def test_source_links_are_pinned_to_the_reviewed_commit(self):
        verdict = {"verdict": "likely-valid", "summary": "source evidence",
                   "reason": "potential defect", "evidence": [{"file": "src/penx_app/cli/app.py", "line": 175}],
                   "missing": [], "duplicate_issue": None, "next_step": "Review"}
        ref = "a" * 40
        output = it.comment("SLP-DEV1/PenX", verdict, source_ref=ref)
        self.assertIn("/blob/" + ref + "/src/penx_app/cli/app.py#L175", output)
        self.assertNotIn("/blob/main/", output)
        fallback = it.comment("SLP-DEV1/PenX", verdict, source_ref="../badref")
        self.assertIn("/blob/main/src/penx_app/cli/app.py#L175", fallback)

    def test_unneeded_requests_for_available_source_are_suppressed(self):
        proposed = {"verdict": "needs-info", "summary": "check code",
                    "reason": "Need details", "evidence": [],
                    "missing": ["Full source code for src/penx_app/cli/app.py",
                                "Implementation of new_scan()",
                                "Exact reproduction steps and logs"]}
        checked = it.validate(
            proposed, [], {"src/penx_app/cli/app.py": {30: "def new_scan():", 31: "    return False"}}
        )
        self.assertEqual(checked["missing"], ["Exact reproduction steps and logs"])

    def _check_evidence(self, excerpt: str, evidence: dict) -> None:
        self.assertLessEqual(len(excerpt), it.MAX_FILE_CHARS)
        for file, indexed in evidence.items():
            self.assertIn("FILE " + file + ":", excerpt)
            for n, line in indexed.items():
                self.assertIn(f"L{n}: {line}", excerpt)


if __name__ == "__main__":
    import unittest
    unittest.main(verbosity=2)
