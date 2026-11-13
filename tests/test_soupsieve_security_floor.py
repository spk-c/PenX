"""Regression for CVE-2026-126190 dependency floor and HTML selector behavior.

Uses only local synthetic HTML; no network, scanner or public vulnerability feed.
"""
from pathlib import Path
import re
import unittest

from bs4 import BeautifulSoup
from packaging.requirements import Requirement
from packaging.version import Version

ROOT = Path(__file__).resolve().parents[1]


class SoupSieveSecurityFloorTests(unittest.TestCase):
    def test_direct_requirement_excludes_pre_fix_versions(self):
        deps = (ROOT / "requirements.txt").read_text(encoding="utf-8")
        spec = next(line for line in deps.splitlines()
                    if line.startswith("soupsieve"))
        req = Requirement(spec)
        self.assertEqual(req.name, "soupsieve")
        self.assertIn(Version("4.1"), req.specifier)
        for old in ("2.10", "3.0.4"):
            self.assertNotIn(Version(old), req.specifier)

    def test_hash_lock_uses_patched_version(self):
        contents = (ROOT / "requirements.lock.txt").read_text(encoding="utf-8")
        match = re.search(r"(?m)^soupsieve==(\d+(?:\.\d+)+) \\\s*$", contents)
        self.assertIsNotNone(match)
        self.assertGreaterEqual(Version(match.group(1)), Version("4.0"))
        section = contents[match.end():contents.index("# via -r requirements.txt", match.end())]
        self.assertEqual(len(re.findall(r"--hash=sha256:[0-9a-f]{64}", section)), 2)

    def test_nested_synthetic_html_selector_still_matches(self):
        html = "<section>" + "<div>" * 32 + '<span id="safe">ok</span>' + "</div>" * 32 + "</section>"
        doc = BeautifulSoup(html, "html.parser")
        self.assertEqual([node.get_text() for node in doc.select("section div span#safe")],
                         ["ok"])
        self.assertEqual(doc.select_one("section > div").name, "div")


if __name__ == "__main__":
    unittest.main()
