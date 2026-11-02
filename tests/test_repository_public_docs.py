"""Keep the public landing page aligned with the actual published release.

These static tests are offline and do not query GitHub or scan hosts.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]


class RepositoryPublicDocsTests(unittest.TestCase):
    def test_public_links_and_linux_checksum_are_discoverable(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        from penx_app.version import VERSION
        for asset in (
            "PenX-Setup-x64.exe",
            "PenX-Windows-x64.zip",
            f"penx_{VERSION}_amd64.deb",
            "PenX-Linux-x86_64.tar.gz",
            "SHA256SUMS.txt",
            "SHA256SUMS-Linux.txt",
        ):
            self.assertIn(asset, readme)
        self.assertIn(f"/releases/tag/v{VERSION}", readme)
        self.assertNotIn("Linux support in development", readme)
        self.assertNotIn("published release still provides Windows binaries only", readme)

    def test_draft_manifests_pin_published_archive(self):
        scoop = json.loads((ROOT / "packaging/scoop/penx.json").read_text())
        from penx_app.version import VERSION
        self.assertEqual(scoop["version"], VERSION)
        self.assertEqual(
            scoop["architecture"]["64bit"]["url"],
            f"https://github.com/spk-c/PenX/releases/download/v{VERSION}/PenX-Windows-x64.zip",
        )
        digest = scoop["architecture"]["64bit"]["hash"]
        self.assertRegex(digest, r"^[0-9a-f]{64}$")
        packaging = (ROOT / "docs/PACKAGING.md").read_text()
        self.assertIn(digest, packaging)
        self.assertIn("draft", packaging.lower())
        self.assertIn("NOT SIGNED OFF", packaging)

    def test_topics_are_grounded_and_within_github_limit(self):
        doc = (ROOT / "docs/REPOSITORY_METADATA.md").read_text()
        topics = re.search(r"```text\n([^\n`]+(?:\n[^\n`]+)*)\n```", doc)
        self.assertIsNotNone(topics)
        values = topics.group(1).splitlines()
        self.assertLessEqual(len(values), 20)
        self.assertEqual(len(values), len(set(values)))
        self.assertTrue({"kali-linux", "linux", "windows", "local-ai", "nmap", "nuclei"}.issubset(values))
        self.assertIn("does **not** apply", doc)


if __name__ == "__main__":
    unittest.main()
