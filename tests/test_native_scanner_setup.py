"""No-network test coverage of signed-digest Windows setup metadata checks."""
import unittest
import os
import subprocess
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from penx_app.setup.native_scanner_setup import _asset_for, SOURCES


class NativeSetupTests(unittest.TestCase):
    def test_initial_template_install_allows_ten_minutes_and_checks_actual_directory(self):
        from penx_app.setup.native_scanner_setup import install_nuclei_templates
        with tempfile.TemporaryDirectory() as folder:
            location = Path(folder) / "templates"
            def fake_update(argv, **kwargs):
                self.assertEqual(argv[:2], ["nuclei.exe", "-update-templates"])
                self.assertEqual(argv[-2:], ["-update-template-dir", str(location)])
                self.assertEqual(kwargs["timeout"], 600)
                (location / "http").mkdir()
                (location / "http" / "example.yaml").write_text("id: offline-test", encoding="utf-8")
                return SimpleNamespace(returncode=0, stdout="", stderr="")
            with patch.dict(os.environ, {"PENX_NUCLEI_TEMPLATE_TIMEOUT": "600"}), \
                 patch("penx_app.setup.native_scanner_setup.subprocess.run", side_effect=fake_update):
                self.assertTrue(install_nuclei_templates("nuclei.exe", location))
                self.assertFalse((location / ".penx-template-update-incomplete").exists())

    def test_timeout_does_not_mark_partial_template_download_ready(self):
        from penx_app.setup.native_scanner_setup import install_nuclei_templates
        with tempfile.TemporaryDirectory() as folder:
            location = Path(folder) / "templates"
            location.mkdir()
            (location / "partial.yaml").write_text("id: partial", encoding="utf-8")
            error = subprocess.TimeoutExpired(["nuclei.exe"], 600, stderr=b"slow Github download")
            with patch("penx_app.setup.native_scanner_setup.subprocess.run", side_effect=error):
                self.assertFalse(install_nuclei_templates("nuclei.exe", location))
            from penx_app.scanners.native_web_scanners import has_nuclei_templates
            self.assertTrue((location / ".penx-template-update-incomplete").is_file())
            self.assertFalse(has_nuclei_templates(location))

    def test_configured_timeout_is_bounded(self):
        from penx_app.setup.native_scanner_setup import install_nuclei_templates
        with tempfile.TemporaryDirectory() as folder:
            location = Path(folder)
            (location / "valid.yml").write_text("id: available", encoding="utf-8")
            with patch.dict(os.environ, {"PENX_NUCLEI_TEMPLATE_TIMEOUT": "900"}), \
                 patch("penx_app.setup.native_scanner_setup.subprocess.run", return_value=SimpleNamespace(
                     returncode=0, stdout="", stderr="")) as run:
                self.assertTrue(install_nuclei_templates("nuclei.exe", location))
            self.assertEqual(run.call_args.kwargs["timeout"], 900)

    def test_custom_template_folder_shared_by_setup_and_scan(self):
        from penx_app.scanners.native_web_scanners import template_install_directory, nuclei_templates
        with tempfile.TemporaryDirectory() as folder:
            location = Path(folder) / "custom"
            location.mkdir()
            (location / "sample.yaml").write_text("id: offline-test", encoding="utf-8")
            with patch.dict(os.environ, {"PENX_NUCLEI_TEMPLATES": str(location)}):
                self.assertEqual(template_install_directory(), location)
                self.assertEqual(nuclei_templates(), location)

    def test_official_windows_amd64_asset_with_digest(self):
        meta = {"assets": [{
            "name": "nuclei_3.11.1_windows_amd64.zip",
            "size": 3000,
            "digest": "sha256:" + "a" * 64,
            "browser_download_url":
                "https://github.com/projectdiscovery/nuclei/releases/download/v3.11.1/nuclei_3.11.1_windows_amd64.zip",
        }]}
        asset = _asset_for("nuclei", meta)
        self.assertEqual(asset["digest"], "a" * 64)
        self.assertTrue(asset["url"].startswith("https://github.com/"))

    def test_redirects_must_remain_on_github_https_or_asset_cdn(self):
        from unittest.mock import Mock, patch
        from penx_app.setup.native_scanner_setup import _http_get

        for final in ("http://github.com/download", "https://attacker.example/file.zip",
                      "https://github.com.attacker.example/file.zip"):
            with self.subTest(final=final):
                response = Mock(url=final)
                with patch("penx_app.setup.native_scanner_setup.requests.get", return_value=response):
                    with self.assertRaises(ValueError):
                        _http_get("https://api.github.com/repos/test/release")
                response.close.assert_called_once()
        for final in ("https://api.github.com/repos/test/release",
                      "https://release-assets.githubusercontent.com/download"):
            with self.subTest(final=final):
                response = Mock(url=final)
                with patch("penx_app.setup.native_scanner_setup.requests.get", return_value=response):
                    self.assertIs(_http_get("https://api.github.com/repos/test/release"), response)
                response.close.assert_not_called()

    def test_new_scanners_use_verified_official_releases(self):
        for name in ("subfinder", "katana"):
            with self.subTest(name=name):
                self.assertEqual(SOURCES[name], f"projectdiscovery/{name}")
                release_asset = f"{name}_1.2.3_windows_amd64.zip"
                meta = {"assets": [{
                    "name": release_asset,
                    "size": 1024,
                    "digest": "sha256:" + "b" * 64,
                    "browser_download_url":
                        f"https://github.com/projectdiscovery/{name}/releases/download/v1.2.3/{release_asset}",
                }]}
                asset = _asset_for(name, meta)
                self.assertEqual(asset["digest"], "b" * 64)
                meta["assets"][0]["browser_download_url"] = (
                    f"https://github.com/attacker/{name}/releases/download/v1.2.3/{release_asset}"
                )
                with self.assertRaises(ValueError):
                    _asset_for(name, meta)
                meta["assets"][0]["browser_download_url"] = (
                    f"https://github.com/projectdiscovery/{name}/releases/download/v1.2.3/{release_asset}"
                )
                del meta["assets"][0]["digest"]
                with self.assertRaises(ValueError):
                    _asset_for(name, meta)

    def test_missing_digest_fails_closed(self):
        meta = {"assets": [{
            "name": "ffuf_2.3.0_windows_amd64.zip",
            "size": 3000,
            "browser_download_url":
                "https://github.com/ffuf/ffuf/releases/download/v2.3.0/ffuf_2.3.0_windows_amd64.zip",
        }]}
        with self.assertRaises(ValueError):
            _asset_for("ffuf", meta)

    def test_other_project_release_url_refused(self):
        meta = {"assets": [{
            "name": "httpx_1.12.0_windows_amd64.zip",
            "size": 3000, "digest": "sha256:" + "f" * 64,
            "browser_download_url":
                "https://github.com/other/project/releases/download/v1.12.0/httpx_1.12.0_windows_amd64.zip",
        }]}
        with self.assertRaises(ValueError):
            _asset_for("httpx", meta)

    def test_zipbomb_size_cap(self):
        meta = {"assets": [{
            "name": "nuclei_3.11.1_windows_amd64.zip",
            "size": 999999999,
            "digest": "sha256:" + "a" * 64,
            "browser_download_url":
                "https://github.com/projectdiscovery/nuclei/releases/download/v3.11.1/nuclei_3.11.1_windows_amd64.zip",
        }]}
        with self.assertRaises(ValueError):
            _asset_for("nuclei", meta)


if __name__ == "__main__":
    unittest.main()
