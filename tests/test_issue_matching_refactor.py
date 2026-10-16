"""Deterministic issue matching remains safe under split script/package imports."""
from __future__ import annotations

from pathlib import Path
import os
import subprocess
import sys
import unittest

from scripts import issue_matching
from scripts import issue_triage


ROOT = Path(__file__).resolve().parents[1]


class MatchingRefactorTests(unittest.TestCase):
    def test_identical_duplicate_scores_through_legacy_facade(self):
        issue = {"number": 52, "title": "Windows scanner crashes when Nmap missing",
                 "body": "run_nmap() in src/tools.py returns an error"}
        others = [{"number": 42, "title": issue["title"], "body": issue["body"]},
                  {"number": 52, "title": issue["title"]},
                  {"number": 53, "title": "Unrelated feature request",
                   "pull_request": {"url": "pull"}}]
        self.assertEqual(issue_matching.find_duplicates(issue, others),
                         issue_triage.duplicates(issue, others))
        self.assertEqual([x["number"] for x in issue_matching.find_duplicates(issue, others)], [42])

    def test_credentials_redacted_in_both_modes(self):
        secret = "sk-" + "X" * 30
        sample = f"API_KEY={secret}\nBearer {secret}"
        self.assertEqual(issue_triage.redact_secrets(sample),
                         issue_matching.redact_text_secrets(sample))
        self.assertNotIn(secret, issue_triage.redact_secrets(sample))

    def test_matching_terms_are_unchanged(self):
        value = "Crash in run_nmap() src/tools.py"
        self.assertEqual(issue_triage.tokens(value), issue_matching.token_terms(value))
        self.assertEqual(issue_triage._technical_signatures(value),
                         issue_matching.signature_terms(value))

    def test_direct_github_actions_entrypoint_still_imports(self):
        env = {**os.environ, "GITHUB_REPOSITORY": ""}
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "issue_triage.py"), "review"],
            cwd=ROOT, env=env, capture_output=True, text=True, timeout=15)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Invalid GITHUB_REPOSITORY", result.stderr)
        self.assertNotIn("ModuleNotFoundError", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
