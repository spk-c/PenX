"""GitHub migration safety: default-branch checks, scheduled cost, and settings."""
from pathlib import Path
import json
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]


class GitHubRepositoryConfigurationTests(unittest.TestCase):
    def test_main_ruleset_requires_pr_and_test_checks(self):
        rules = json.loads((ROOT / ".github/rulesets/protect-main.json").read_text())
        self.assertEqual(rules["enforcement"], "active")
        self.assertEqual(rules["conditions"]["ref_name"]["include"], ["refs/heads/main"])
        types = {rule["type"] for rule in rules["rules"]}
        self.assertTrue({"deletion", "non_fast_forward", "pull_request",
                         "required_status_checks"}.issubset(types))
        required = next(x for x in rules["rules"] if x["type"] == "required_status_checks")
        contexts = {x["context"] for x in required["parameters"]["required_status_checks"]}
        self.assertIn("Windows packaged app & installer", contexts)
        self.assertIn("tests (ubuntu-latest)", contexts)
        self.assertIn("tests (windows-latest)", contexts)

    def test_pull_requests_always_trigger_required_checks(self):
        workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        self.assertRegex(workflow, r"(?m)^  pull_request:\s*$")
        block = workflow.split("  pull_request:", 1)[1].split("  workflow_dispatch:", 1)[0]
        self.assertNotIn("paths-ignore:", block)

    def test_issue_triage_daily_and_on_new_issue(self):
        workflow = (ROOT / ".github/workflows/issue-triage.yml").read_text(encoding="utf-8")
        self.assertRegex(workflow, r"cron:\s*'17 6 \* \* \*'")
        self.assertIn("types: [opened]", workflow)

    def test_old_archive_url_not_misrepresented_as_live_release(self):
        manifest = json.loads((ROOT / "packaging/scoop/penx.json").read_text())
        self.assertEqual(manifest["homepage"], "https://github.com/spk-c/PenX")
        self.assertIn("SLP-DEV1", manifest["architecture"]["64bit"]["url"])
        doc = (ROOT / "docs/PACKAGING.md").read_text(encoding="utf-8")
        self.assertIn("historical", doc.lower())
        self.assertIn("not", doc.lower())

    def test_owner_only_script_is_not_automatically_executed(self):
        script = (ROOT / "scripts/configure_github.ps1").read_text(encoding="utf-8")
        self.assertIn("gh auth status", script)
        self.assertIn("[switch]$PublishRelease", script)
        self.assertIn("Windows packaged app & installer", script)
        self.assertIn("repos/$repo/git/refs", script)


if __name__ == "__main__":
    unittest.main()
