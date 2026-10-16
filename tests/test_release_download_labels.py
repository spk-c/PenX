"""Release downloads should be unambiguous in README and generated releases."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ReleaseDownloadLabelTests(unittest.TestCase):
    def test_release_guide_distinguishes_downloads(self):
        guide = (ROOT / ".github" / "RELEASE_DOWNLOAD_GUIDE.md").read_text(encoding="utf-8")
        self.assertIn("penx-download-options-v1", guide)
        self.assertIn("PenX-Setup-x64.exe", guide)
        self.assertIn("PenX-Windows-x64.zip", guide)
        self.assertIn("Recommended", guide)
        self.assertIn("Portable (no installation)", guide)
        self.assertIn("Source code (zip)", guide)

    def test_readme_links_are_distinct_and_recommend_installer(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("/releases/latest/download/PenX-Setup-x64.exe", readme)
        self.assertIn("/releases/latest/download/PenX-Windows-x64.zip", readme)
        self.assertIn("### Option A: Windows installer (recommended)", readme)
        self.assertIn("### Option B: Portable Windows release (no installation)", readme)

    def test_future_release_contains_download_guide_and_changelog(self):
        workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
        self.assertIn("releases/generate-notes", workflow)
        self.assertIn(".github/RELEASE_DOWNLOAD_GUIDE.md", workflow)
        self.assertIn("--notes-file RELEASE-NOTES.md", workflow)
        self.assertIn("PenX-Windows-x64.zip PenX-Setup-x64.exe SHA256SUMS.txt", workflow)


if __name__ == "__main__":
    unittest.main(verbosity=2)
