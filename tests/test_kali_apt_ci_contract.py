"""Offline CI contract for handling transient official Kali mirrors."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class KaliAptContractTests(unittest.TestCase):
    def test_kali_smoke_and_release_share_retry_script(self):
        for workflow in ("linux-packaging.yml", "release.yml"):
            text = (ROOT / ".github" / "workflows" / workflow).read_text(
                encoding="utf-8"
            )
            with self.subTest(workflow=workflow):
                self.assertIn("ci_kali_apt_install.sh:/ci_kali_apt_install.sh:ro", text)
                self.assertIn("bash /ci_kali_apt_install.sh /artifacts/penx_", text)

    def test_fallback_is_official_only_and_never_swallow_errors(self):
        script = (ROOT / "scripts" / "ci_kali_apt_install.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("set -euo pipefail", script)
        self.assertIn("Acquire::Retries=3", script)
        self.assertIn("https://kali.download/kali", script)
        self.assertIn("kali.sources", script)
        self.assertIn("sources.list", script)
        self.assertIn('install_packages "$@"', script)
        self.assertNotIn("trusted=yes", script)
        self.assertNotIn("AllowUnauthenticated", script)


if __name__ == "__main__":
    unittest.main()
