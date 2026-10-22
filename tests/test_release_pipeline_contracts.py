"""Offline regression contracts for the supported GitHub release pipeline.

Keep these assertions version-independent: old version-specific publisher
workflows and duplicate release-note files are not runtime dependencies.
"""
from __future__ import annotations

import importlib
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
RELEASE = ROOT / ".github/workflows/release.yml"
CI = ROOT / ".github/workflows/ci.yml"


class ReleasePipelineContracts(unittest.TestCase):
    def test_source_package_versions_match(self):
        version = importlib.import_module("penx_app.version").VERSION
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertRegex(version, r"^\d+\.\d+\.\d+$")
        self.assertIn(f'version = "{version}"', pyproject)

    def test_tagged_release_is_version_checked_and_never_force_published(self):
        workflow = RELEASE.read_text(encoding="utf-8")
        self.assertIn("  push:\n    tags:", workflow)
        self.assertIn("github.ref_type == 'tag'", workflow)
        self.assertIn("'v' + VERSION", workflow)
        self.assertIn("python offline_tests.py", workflow)
        self.assertIn("--verify-tag", workflow)
        self.assertIn("gh release create", workflow)
        self.assertNotIn("--force", workflow)

    def test_windows_release_is_dispatchable_for_an_explicit_tag(self):
        workflow = RELEASE.read_text(encoding="utf-8")
        self.assertIn("workflow_dispatch:", workflow)
        self.assertIn("github.ref_type == 'tag'", workflow)
        self.assertIn("PenX-Windows-x64.zip", workflow)
        self.assertIn("PenX-Setup-x64.exe", workflow)
        self.assertIn("SHA256SUMS.txt", workflow)
        self.assertIn(".github/RELEASE_DOWNLOAD_GUIDE.md", workflow)

    def test_required_checks_remain_in_main_ci(self):
        workflow = CI.read_text(encoding="utf-8")
        self.assertIn("pull_request:", workflow)
        self.assertIn("windows-latest", workflow)
        self.assertIn("ubuntu-latest", workflow)
        self.assertIn("Windows packaged app & installer", workflow)
        self.assertIn("python offline_tests.py", workflow)
        security = (ROOT / ".github/workflows/security.yml").read_text(encoding="utf-8")
        self.assertIn("Gitleaks", security)

    def test_current_release_status_and_operator_limits_remain_public(self):
        status = (ROOT / "docs/MAINTENANCE_STATUS.md").read_text(encoding="utf-8")
        packaging = (ROOT / "docs/PACKAGING.md").read_text(encoding="utf-8")
        version = importlib.import_module("penx_app.version").VERSION
        # Version may advance in source before a publishable Windows build exists.
        published = json.loads((ROOT / "packaging/scoop/penx.json").read_text())
        published_version = published["version"]
        self.assertIn(f"/releases/tag/v{published_version}", status)
        self.assertIn(f"v{version}", status)
        self.assertIn("NOT SIGNED OFF", status)
        self.assertIn(f"v{version}", packaging)
        self.assertIn("draft", packaging.lower())
        self.assertIn(f'#define MyAppVersion "{version}"',
                      (ROOT / "installer/penx.iss").read_text())
        guide = (ROOT / ".github/RELEASE_DOWNLOAD_GUIDE.md").read_text()
        self.assertIn("NOT SIGNED OFF", guide)
        if published_version != version:
            self.assertIn("source-only release candidate", packaging)
            self.assertIn("publication is pending", status)


if __name__ == "__main__":
    unittest.main()
