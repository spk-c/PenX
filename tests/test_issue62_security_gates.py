"""Source-only regressions for GitHub issue #62 hardening.

These tests make no network requests, start no installers and read no secrets.
"""
from __future__ import annotations

from pathlib import Path
import re
import unittest
from unittest.mock import patch

import install_scanners_windows as installer


ROOT = Path(__file__).resolve().parents[1]


class Issue62SecurityGatesTests(unittest.TestCase):
    def test_upstream_source_archives_use_reviewed_immutable_commits(self):
        for url, revision in (
            (installer.WHATWEB_URL, installer.WHATWEB_COMMIT),
            (installer.NIKTO_URL, installer.NIKTO_COMMIT),
        ):
            self.assertRegex(revision, r"^[0-9a-f]{40}$")
            self.assertTrue(url.startswith("https://github.com/"))
            self.assertTrue(url.endswith("/archive/" + revision + ".zip"))
            self.assertNotIn("/refs/heads/", url)
            self.assertNotIn("/refs/tags/", url)

    def test_reject_insecure_and_cross_publisher_redirects(self):
        class Response:
            def __init__(self, url):
                self.url = url
            def geturl(self):
                return self.url

        allowed_gh = {"github.com", "codeload.github.com"}
        allowed_nmap = {"nmap.org", "www.nmap.org"}
        for url in ("http://codeload.github.com/a.zip",
                    "https://github.com.attacker.example/a.zip",
                    "https://files.attacker.example/a.zip"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                installer._validate_download_origin(Response(url), allowed_gh)
        installer._validate_download_origin(
            Response("https://codeload.github.com/urbanadventurer/WhatWeb/zip/a"),
            allowed_gh)
        installer._validate_download_origin(Response("https://nmap.org/dist/setup.exe"),
                                            allowed_nmap)
        with self.assertRaises(ValueError):
            installer._validate_download_origin(Response("https://example.com/setup.exe"),
                                                allowed_nmap)

    def test_github_archive_redirect_is_checked_before_untrusted_bytes(self):
        class Response:
            def __enter__(self): return self
            def __exit__(self, *_): return False
            def geturl(self): return "http://codeload.github.com/bad.zip"
            def read(self, _): raise AssertionError("Untrusted bytes must not be read")
        with patch.object(installer, "urlopen", return_value=Response()):
            with self.assertRaises(ValueError):
                installer.download_archive(installer.WHATWEB_URL)

    def test_security_workflow_has_all_critical_checks(self):
        workflow = (ROOT / ".github/workflows/security.yml").read_text(encoding="utf-8")
        for required in ("Gitleaks", "CodeQL", "Dependency changes policy",
                         "fetch-depth: 0", "security-events: write", "pull_request:"):
            self.assertIn(required, workflow)
        self.assertNotIn("continue-on-error: true", workflow)
        # Third-party actions must reference reviewed immutable commit hashes.
        actions = re.findall(r"uses: ((?:gitleaks/gitleaks-action|actions/dependency-review-action|"
                             r"github/codeql-action/[^@]+)@([^\s#]+))", workflow)
        self.assertGreaterEqual(len(actions), 4)
        for _, revision in actions:
            self.assertRegex(revision, r"^[a-f0-9]{40}$")

    def test_batch_entrypoints_do_not_use_dynamic_shell_powershell(self):
        for path in ROOT.glob("*.bat"):
            source = path.read_text(encoding="utf-8").lower()
            with self.subTest(path=path.name):
                self.assertNotIn("powershell -command %", source)
                self.assertNotIn("cmd /c %", source)
                self.assertNotIn("setx path", source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
