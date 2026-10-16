"""Regression coverage for issue #58's source-only Groq triage.

No issue-provided code is run, no model endpoint is contacted and no
repository issues are edited by these tests.
"""
from pathlib import Path
import unittest

from scripts import issue_triage as it

ROOT = Path(__file__).resolve().parents[1]


def issue58():
    return {
        "number": 58,
        "title": "Low: missing try/except on edit_exploit / edit_fix / edit_summary_risk",
        "body": (
            "File: src/penx_app/cli/app.py -> edit_delete_menu(). "
            "Unprotected edit_exploit(), edit_fix(), edit_summary_risk() calls "
            "versus edit_vulnerability() and edit_correction(). "
            "Inspect src/penx_app/storage/db.py helper return values as well. "
            "Errors should be handled, and a success message must not be "
            "emitted when a database update changes no row. "
            "Related: #43."
        ),
    }


class Issue58TriageTests(unittest.TestCase):
    def test_direct_helper_is_included_when_edit_functions_are_named(self):
        lines = (ROOT / "src/penx_app/storage/db.py").read_text(encoding="utf-8").splitlines()
        groups = it._source_groups(
            lines, "edit_fix() and edit_exploit() call into a helper. "
                   "Check return values, no-op updates, and success messages.")
        selected = {lines[i].strip() for group in groups for i in group}
        self.assertIn("def _scoped_write(table: str, row_id: int, sl_no: int, changes: dict) -> bool:", selected)
        self.assertIn("updated = cursor.rowcount > 0", selected)
        self.assertIn("return updated", selected)

    def test_review_context_traces_cli_calls_and_db_helper(self):
        excerpt, checked = it.code_context(ROOT, issue58())
        self.assertIn("FILE src/penx_app/cli/app.py:", excerpt)
        self.assertIn("FILE src/penx_app/storage/db.py:", excerpt)
        self.assertIn("def _scoped_write(", excerpt)
        self.assertIn("return updated", excerpt)
        self.assertIn("edit_summary_risk(", excerpt)
        self.assertIn("src/penx_app/storage/db.py", checked)
        self.assertLessEqual(len(excerpt), it.MAX_FILE_CHARS)

    def test_issue_finding_labels_do_not_link_unrelated_prs(self):
        assessment = {
            "verdict": "partially-supported",
            "summary": "Two paths confirmed",
            "reason": "CLI has unhandled edit calls",
            "impact": "Unexpected DB errors could reach the CLI",
            "findings": [
                {"id": "1", "status": "supported", "reason": "Call not wrapped"},
                {"id": "2", "status": "inconclusive", "reason": "Not verified"},
            ],
            "evidence": [],
            "missing": [],
            "next_step": "Add regression coverage",
            "duplicate_issue": None,
        }
        comment = it.comment("SLP-DEV1/PenX", assessment)
        self.assertIn("**Finding 1: Source-supported**", comment)
        self.assertIn("**Finding 2: Not verified**", comment)
        self.assertNotIn("**#1:", comment)
        self.assertIn("Source inspection only", comment)
        self.assertIn("Potential impact (not runtime-tested)", comment)

    def test_untrusted_model_cannot_claim_test_execution_status(self):
        proposed = {
            "category": "bug", "verdict": "unverified",
            "verification": "tests-executed", "tests_passed": 999,
            "summary": "Review needed",
            "impact": "Could cause a traceback on database failure",
            "reason": "The call is not wrapped in try/except",
            "evidence": [], "missing": [],
        }
        result = it.validate(proposed, [], {})
        self.assertEqual(result["verification"], "source-inspection-only")
        self.assertNotIn("tests_passed", result)
        comment = it.comment("SLP-DEV1/PenX", result)
        self.assertIn("did not execute regression tests", comment)
        self.assertNotIn("999", comment)


if __name__ == "__main__":
    unittest.main(verbosity=2)
