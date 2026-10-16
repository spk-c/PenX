"""Guard GitLab release download messaging and Windows publication contracts."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ReleaseDownloadLabelTests(unittest.TestCase):
    def test_readme_uses_gitlab_and_does_not_claim_unpublished_binaries(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("https://gitlab.com/SLP-DEV1/PenX.git", readme)
        self.assertIn("/-/releases", readme)
        self.assertIn("PenX-Setup-x64.exe", readme)
        self.assertIn("PenX-Windows-x64.zip", readme)
        self.assertNotIn("https://github.com/SLP-DEV1/PenX", readme)
        self.assertNotIn("/releases/latest/download/PenX-Setup-x64.exe", readme)

    def test_release_guide_preserves_artifact_distinctions(self):
        guide = (ROOT / ".github" / "RELEASE_DOWNLOAD_GUIDE.md").read_text(encoding="utf-8")
        self.assertIn("PenX-Setup-x64.exe", guide)
        self.assertIn("PenX-Windows-x64.zip", guide)
        self.assertIn("SHA256SUMS.txt", guide)
        self.assertIn("No Windows binaries", guide)
        self.assertIn("source installation", guide)

    def test_tag_windows_build_and_release_only_after_verified_artifacts(self):
        workflow = (ROOT / ".gitlab-ci.yml").read_text(encoding="utf-8")
        build = (ROOT / "scripts" / "gitlab_windows_release.ps1").read_text(encoding="utf-8")
        publisher = (ROOT / "scripts" / "gitlab_publish_release.py").read_text(encoding="utf-8")
        self.assertIn("saas-windows-medium-amd64", workflow)
        self.assertIn("publish-gitlab-release:", workflow)
        self.assertIn("needs:", workflow)
        self.assertIn("SHA256SUMS.txt", build)
        self.assertIn("Assert-ExitCode 'Offline regression tests'", build)
        self.assertIn("SHA256SUMS.txt", publisher)
        self.assertIn("hashlib.sha256", publisher)
        self.assertIn("CI_JOB_TOKEN", publisher)


if __name__ == "__main__":
    unittest.main(verbosity=2)
