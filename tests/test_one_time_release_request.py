"""Static safeguards for the one-time v0.6.1 release publication request.

Only reads local workflow/metadata; no network, tags, secrets or releases.
"""
from __future__ import annotations

import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"
REQUEST = ROOT / ".github" / "release-requests" / "v0.6.1.json"


class OneTimeReleaseContractTests(unittest.TestCase):
    def test_request_is_pinned_to_reviewed_parent(self):
        request = json.loads(REQUEST.read_text(encoding="utf-8"))
        self.assertEqual(request["schema"], "penx-one-time-release-v1")
        self.assertEqual(request["version"], "0.6.1")
        self.assertEqual(request["tag"], "v0.6.1")
        self.assertEqual(
            request["source_parent_sha"],
            "1e26f262b89f791e99e179ee76c53caef653ee22",
        )

    def test_only_one_time_file_can_trigger_main_push_release(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        header = workflow.split("  pull_request:", maxsplit=1)[0]
        self.assertIn("    tags:\n      - 'v*'", header)
        self.assertIn("    branches:\n      - main", header)
        self.assertIn(
            "    paths:\n      - '.github/release-requests/v0.6.1.json'",
            header,
        )
        self.assertIn("github.ref == 'refs/heads/main'", workflow)
        self.assertIn("request[\"source_parent_sha\"]", workflow)
        self.assertIn("gh api --method POST", workflow)
        self.assertIn("refs/tags/$env:TAG", workflow)

    def test_publication_requires_complete_bundle_verification(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertLess(
            workflow.index("python release_supply_chain.py verify-release release-bundle"),
            workflow.index("- name: Publish the explicitly approved v0.6.1 release"),
        )
        self.assertIn('--expect-commit "$env:GITHUB_SHA"', workflow)
        self.assertIn("--verify-tag", workflow)
        self.assertIn("NOT SIGNED OFF", (
            ROOT / "docs" / "RELEASE_0.6.1_NOTES.md"
        ).read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
