"""Regression contracts for low-usage GitHub Actions settings."""
from pathlib import Path
import unittest

WF = Path(__file__).resolve().parents[1] / ".github" / "workflows"


def read(name: str) -> str:
    return (WF / name).read_text(encoding="utf-8")


class ActionsBudgetTests(unittest.TestCase):
    def test_pr_linux_checks_and_manual_windows(self):
        s = read("ci.yml")
        self.assertIn("  pull_request:", s)
        # Merged main commits need verification; superseded runs are cancelled
        # rather than doubling the Windows or scheduled security budget.
        self.assertIn("  push:\n    branches: [main]", s)
        self.assertIn("cancel-in-progress: true", s)
        self.assertIn("name: tests (ubuntu-latest)", s)
        self.assertIn("name: tests (windows-latest)", s)
        # Only release PRs or manual runs consume Windows minutes.
        self.assertIn("startsWith(github.head_ref, 'release/')", s)
        self.assertIn("if: github.event_name == 'workflow_dispatch' ||", s)
        self.assertIn("name: Windows packaged app & installer", s)
        self.assertIn("python offline_tests.py", s)

    def test_security_pr_secrets_and_weekly_sast(self):
        s = read("security.yml")
        self.assertIn("  schedule:", s)
        self.assertIn("  pull_request:", s)
        self.assertNotIn("  push:\n    branches: [main]", s)
        self.assertIn("Gitleaks history and change scan", s)
        self.assertEqual(s.count("if: github.event_name != 'pull_request'"), 2)

    def test_compatibility_and_triage_budget(self):
        p = read("python-compatibility.yml")
        self.assertIn("  workflow_dispatch:", p)
        self.assertNotIn("  pull_request:", p)
        self.assertNotIn("  push:", p)
        self.assertIn("['3.10', '3.11', '3.12', '3.13']", p)
        i = read("issue-triage.yml")
        self.assertNotIn("  schedule:", i)
        self.assertIn("types: [opened]", i)

    def test_db_targeted_and_release_retained(self):
        m = read("mariadb-integration.yml")
        self.assertIn("  pull_request:", m)
        self.assertIn("  workflow_dispatch:", m)
        self.assertNotIn("  push:", m)
        r = read("release.yml")
        self.assertIn("  push:\n    tags:", r)
        self.assertIn("python offline_tests.py", r)
        self.assertIn("PenX-Setup-x64.exe", r)


if __name__ == "__main__":
    unittest.main()
