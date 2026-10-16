"""Verify the GitHub release presentation and tagged build contracts."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
GH = "https://github.com/spk-c/PenX"


class ReleaseDownloadLabelTests(unittest.TestCase):
    def test_readme_current_github_home(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn(GH + ".git", readme)
        self.assertIn(GH + "/releases", readme)
        self.assertIn("PenX-Setup-x64.exe", readme)
        self.assertIn("PenX-Windows-x64.zip", readme)
        self.assertNotIn("https://gitlab.com/SLP-DEV1/PenX", readme)

    def test_release_guide_is_unambiguous(self):
        guide = (ROOT / ".github" / "RELEASE_DOWNLOAD_GUIDE.md").read_text(encoding="utf-8")
        for phrase in ("penx-download-options-v1", "PenX-Setup-x64.exe",
                       "PenX-Windows-x64.zip", "SHA256SUMS.txt",
                       "Portable (no installation)", "Source code (zip)"):
            self.assertIn(phrase, guide)
        self.assertIn(GH + "/releases", guide)

    def test_github_workflow_still_publishes_verified_assets(self):
        workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
        self.assertIn("releases/generate-notes", workflow)
        self.assertIn(".github/RELEASE_DOWNLOAD_GUIDE.md", workflow)
        self.assertIn("--notes-file RELEASE-NOTES.md", workflow)
        self.assertIn("PenX-Windows-x64.zip PenX-Setup-x64.exe SHA256SUMS.txt", workflow)

    def test_updater_points_to_new_owner(self):
        from penx_app import updates
        self.assertEqual(updates.API, "https://api.github.com/repos/spk-c/PenX/releases/latest")
        self.assertEqual(updates.DOWNLOAD_PREFIX, GH + "/releases/download/")


if __name__ == "__main__":
    unittest.main(verbosity=2)
