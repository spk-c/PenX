"""Regression checks for low-cost main verification and safe branch pruning."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]


class RepositoryHygieneContracts(unittest.TestCase):
    def test_main_push_and_pull_requests_run_same_offline_gate(self):
        ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        events = ci.split("on:", 1)[1].split("concurrency:", 1)[0]
        self.assertRegex(events, r"(?m)^  pull_request:\s*$")
        self.assertRegex(events, r"(?m)^  push:\s*$")
        self.assertIn("branches: [main]", events)
        self.assertIn("  workflow_dispatch:", events)
        self.assertIn("cancel-in-progress: true", ci)
        self.assertIn("python offline_tests.py", ci)

    def test_prune_is_opt_in_and_covers_all_topic_prefixes(self):
        script = (ROOT / "scripts/prune_merged_github_branches.ps1").read_text(encoding="utf-8")
        self.assertIn("param([switch]$Apply)", script)
        for prefix in ("chore", "docs", "feat", "feature", "fix",
                       "maintenance", "quality", "refactor", "release"):
            self.assertRegex(script, re.escape(prefix) + r"\|?|/")
        self.assertIn("Get-GhPages", script)
        self.assertIn("Get-Comparison", script)
        self.assertIn("ahead_by", script)
        self.assertIn("merged_at", script)
        self.assertIn("commit.sha -cne $candidate.Sha", script)
        self.assertIn("$current.protected", script)
        self.assertIn("[DRY RUN]", script)
        self.assertIn("if (-not $Apply)", script)
        self.assertIn('gh api -X DELETE', script)
        self.assertNotIn("git push --delete", script)


if __name__ == "__main__":
    unittest.main()
