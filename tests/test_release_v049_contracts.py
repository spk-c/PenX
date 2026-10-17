"""Release v0.4.9 changes must remain attributable to a verified main SHA.

Offline, static checks: no tag creation, API requests or downloads in tests.
"""
from __future__ import annotations

import importlib
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
AUTOMATION = ROOT / ".github/workflows/publish-v0.4.9.yml"


class Release049Contracts(unittest.TestCase):
    def test_source_package_versions_match(self):
        version = importlib.import_module("penx_app.version").VERSION
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertRegex(version, r"^\d+\.\d+\.\d+$")
        self.assertIn(f'version = "{version}"', pyproject)

    def test_new_tag_is_immutable_and_guarded_by_main_sha(self):
        workflow = AUTOMATION.read_text(encoding="utf-8")
        self.assertIn("workflows: [\"Offline tests\"]", workflow)
        self.assertIn("branches: [main]", workflow)
        self.assertIn("github.event.workflow_run.conclusion == 'success'", workflow)
        self.assertIn("github.event.workflow_run.event == 'push'", workflow)
        self.assertIn("EXPECTED_SHA", workflow)
        self.assertIn("main moved before tag", workflow)
        self.assertIn("8dec6ba14a3c082bd05058613db06ff3bf531f75", workflow)
        self.assertIn("git/ref/tags/$RELEASE_TAG", workflow)
        self.assertIn("Release tag exists at a different object", workflow)
        self.assertNotIn("--force", workflow)
        self.assertIn('ref=refs/tags/$RELEASE_TAG', workflow)

    def test_windows_release_runs_on_tag_even_when_created_by_github_token(self):
        workflow = AUTOMATION.read_text(encoding="utf-8")
        released = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        self.assertIn('gh workflow run release.yml --repo "$repo" --ref "$RELEASE_TAG"', workflow)
        self.assertIn("actions: write", workflow)
        self.assertIn("contents: write", workflow)
        self.assertIn("workflow_dispatch:", released)
        self.assertIn("github.ref_type == 'tag'", released)
        self.assertIn("--verify-tag", released)

    def test_all_main_checks_are_mandatory(self):
        workflow = AUTOMATION.read_text(encoding="utf-8")
        for name in (
            "tests (windows-latest)", "tests (ubuntu-latest)",
            "Windows packaged app & installer",
            "Python compatibility contracts", "Security audit",
        ):
            with self.subTest(job=name):
                self.assertIn(name, workflow)
        self.assertIn('peer workflow failed', workflow.lower())
        self.assertIn("Timed out waiting", workflow)

    def test_notes_explicitly_leave_operator_field_acceptance_open(self):
        notes = (ROOT / "docs/RELEASE_0.4.9_NOTES.md").read_text(encoding="utf-8")
        self.assertIn("NOT SIGNED OFF", notes)
        self.assertIn("v0.4.8", notes)
        self.assertIn("v0.4.9", notes)
        self.assertIn("release.yml", notes)


if __name__ == "__main__":
    unittest.main()
