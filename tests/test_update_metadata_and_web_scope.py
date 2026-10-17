"""Offline regressions for release metadata parsing and explicit web target scope."""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from penx_app import updates
from penx_app.scanners.scanner_targets import normalize_web_target, target_urls


class ReleaseMetadataRegressionTests(unittest.TestCase):
    def test_nonstring_release_tags_are_rejected_without_crashing(self):
        for tag in (None, 0, True, [], {}):
            with self.subTest(tag=tag):
                with self.assertRaises(ValueError):
                    updates.version_tuple(tag)
                payload = {"tag_name": tag, "assets": [], "draft": False,
                           "prerelease": False}
                with patch.object(updates, "_read_url",
                                  return_value=json.dumps(payload).encode("utf-8")):
                    self.assertIsNone(updates.check_update(quiet=True))

    def test_bad_asset_names_do_not_hide_legitimate_official_assets(self):
        tag = "v0.4.9"
        payload = {"tag_name": tag, "assets": [
            {"name": ["invalid", "unhashable"], "browser_download_url": "https://invalid.example"},
            {"name": {"invalid": "mapping"}, "browser_download_url": "https://invalid.example"},
            {"name": None, "browser_download_url": "https://invalid.example"},
            {"name": updates.INSTALLER_NAME, "browser_download_url":
                updates.DOWNLOAD_PREFIX + tag + "/" + updates.INSTALLER_NAME},
            {"name": updates.CHECKSUM_NAME, "browser_download_url":
                updates.DOWNLOAD_PREFIX + tag + "/" + updates.CHECKSUM_NAME},
        ]}
        with patch.object(updates, "_read_url",
                          return_value=json.dumps(payload).encode("utf-8")):
            release = updates.fetch_latest()
        self.assertEqual(release.tag, tag)
        self.assertEqual(release.installer_url,
                         updates.DOWNLOAD_PREFIX + tag + "/" + updates.INSTALLER_NAME)
        self.assertEqual(release.checksums_url,
                         updates.DOWNLOAD_PREFIX + tag + "/" + updates.CHECKSUM_NAME)

    def test_future_update_check_marker_does_not_disable_checks(self):
        with tempfile.TemporaryDirectory() as folder:
            marker = Path(folder) / "data" / ".last-update-check"
            marker.parent.mkdir()
            marker.write_text("2000", encoding="ascii")
            old_release = updates.Release("v0.0.1", "", "",
                                          "https://github.com/spk-c/PenX/releases")
            with patch.object(updates, "APP_ROOT", Path(folder)), \
                 patch.object(updates, "installed_mode", return_value=True), \
                 patch.object(updates.time, "time", return_value=1000), \
                 patch.dict(os.environ, {"PENX_AUTO_UPDATE_CHECK": "on"}), \
                 patch.object(updates, "fetch_latest", return_value=old_release) as fetch:
                updates.startup_notice()
            fetch.assert_called_once()
            self.assertEqual(marker.read_text(encoding="ascii"), "1000")


class WebScopeRegressionTests(unittest.TestCase):
    def test_schemeless_paths_and_queries_never_scan_a_different_endpoint(self):
        for target in ("example.test/admin", "example.test/",
                       "example.test?resource=admin", "example.test/#fragment"):
            with self.subTest(target=target):
                with self.assertRaisesRegex(ValueError, "http:// or https://"):
                    normalize_web_target(target)
                with self.assertRaises(ValueError):
                    target_urls(target)

    def test_explicit_urls_and_bare_authorities_remain_valid(self):
        self.assertEqual(normalize_web_target("https://example.test/admin?x=1"),
                         "https://example.test/admin?x=1")
        self.assertEqual(normalize_web_target("example.test:8443"), "example.test:8443")
        self.assertEqual(target_urls("example.test:8443"),
                         ["https://example.test:8443", "http://example.test:8443"])


if __name__ == "__main__":
    unittest.main()
