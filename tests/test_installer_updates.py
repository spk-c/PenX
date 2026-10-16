"""Offline contracts for the Inno Setup package and safe update workflow."""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from penx_app import app_paths, updates
from penx_app.version import VERSION

ROOT = Path(__file__).resolve().parents[1]


class FakeResponse:
    def __init__(self, data: bytes, url: str):
        self.file = io.BytesIO(data)
        self.url = url

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, size: int = -1) -> bytes:
        return self.file.read(size)

    def geturl(self) -> str:
        return self.url


class InstallerUpdateTests(unittest.TestCase):
    def test_versions_share_single_source_of_truth(self):
        self.assertEqual(VERSION, "0.4.6")
        with self.assertRaises(ValueError):
            updates.version_tuple("v0.4.6-rc1")
        self.assertGreater(updates.version_tuple("v0.4.10"), updates.version_tuple("v0.4.9"))
        metadata = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('version = "0.4.6"', metadata)
        self.assertIn("MyAppVersion", (ROOT / "installer" / "penx.iss").read_text())

    def test_installer_paths_are_separate_and_portable_stays_portable(self):
        with tempfile.TemporaryDirectory() as work:
            root = Path(work)
            exe = root / "Programs" / "PenX" / "PenX.exe"
            exe.parent.mkdir(parents=True)
            local = root / "AppData"
            with patch.object(app_paths.sys, "frozen", True, create=True), \
                 patch.object(app_paths.sys, "executable", str(exe)), \
                 patch.dict(os.environ, {"LOCALAPPDATA": str(local)}):
                self.assertFalse(app_paths.installed_mode())
                self.assertEqual(app_paths.application_root(), exe.parent.resolve())
                (exe.parent / ".penx-installed").write_text("installed", encoding="ascii")
                self.assertTrue(app_paths.installed_mode())
                self.assertEqual(app_paths.application_root(), local / "PenX")

    def test_stable_release_assets_must_be_official(self):
        tag = "v0.4.7"
        payload = [{"tag_name": tag, "assets": {"links": [
            {"name": "PenX-Setup-x64.exe", "direct_asset_url": updates._asset_url(tag, updates.INSTALLER_NAME)},
            {"name": "SHA256SUMS.txt", "direct_asset_url": updates._asset_url(tag, updates.CHECKSUM_NAME)},
        ]}}]
        with patch.object(updates, "_read_url", return_value=json.dumps(payload).encode()):
            release = updates.fetch_latest()
        self.assertEqual(release.tag, tag)
        self.assertTrue(updates.is_newer(release))
        payload[0]["assets"]["links"][0]["direct_asset_url"] = "https://evil.example/PenX-Setup-x64.exe"
        with patch.object(updates, "_read_url", return_value=json.dumps(payload).encode()):
            release = updates.fetch_latest()
        self.assertFalse(release.installer_url)

    def test_pre_release_is_never_offered(self):
        payload = [{"tag_name": "v0.5.0-rc1", "assets": {"links": []}}]
        with patch.object(updates, "_read_url", return_value=json.dumps(payload).encode()):
            with self.assertRaises(ValueError):
                updates.fetch_latest()

    def test_missing_checksum_fails_closed(self):
        payload = [{"tag_name": "v0.5.0", "assets": {"links": [
            {"name": updates.INSTALLER_NAME, "direct_asset_url": updates._asset_url("v0.5.0", updates.INSTALLER_NAME)},
        ]}}]
        with patch.object(updates, "_read_url", return_value=json.dumps(payload).encode()):
            with self.assertRaisesRegex(ValueError, "checksum"):
                updates.fetch_latest()

    def test_checksum_protects_installer_and_cleans_corruption(self):
        release = updates.Release(
            "v0.4.7",
            updates.DOWNLOAD_PREFIX + "v0.4.7/downloads/PenX-Setup-x64.exe",
            updates.DOWNLOAD_PREFIX + "v0.4.7/downloads/SHA256SUMS.txt",
            "https://gitlab.com/SLP-DEV1/PenX/-/releases/v0.4.7")
        payload = b"synthetic installer bytes"
        checksum = hashlib.sha256(payload).hexdigest()
        with tempfile.TemporaryDirectory() as root:
            with patch.object(updates, "_read_url", return_value=f"{checksum}  PenX-Setup-x64.exe\n".encode()), \
                 patch.object(updates, "urlopen", return_value=FakeResponse(
                     payload, "https://storage.googleapis.com/gitlab-release-test/object")):
                output = updates.download_verified_installer(release, root=Path(root))
            self.assertEqual(output.read_bytes(), payload)
            output.unlink()
            with patch.object(updates, "_read_url", return_value=f"{checksum}  PenX-Setup-x64.exe\n".encode()), \
                 patch.object(updates, "urlopen", return_value=FakeResponse(
                     b"tampered", "https://storage.googleapis.com/gitlab-release-test/object")):
                with self.assertRaisesRegex(ValueError, "SHA-256"):
                    updates.download_verified_installer(release, root=Path(root))
            self.assertEqual(list((Path(root) / "updates").glob("*.exe")), [])

    def test_update_requires_installed_mode_and_explicit_consent(self):
        release = updates.Release(
            "v0.4.7", updates.DOWNLOAD_PREFIX + "v0.4.7/downloads/PenX-Setup-x64.exe",
            updates.DOWNLOAD_PREFIX + "v0.4.7/downloads/SHA256SUMS.txt",
            "https://gitlab.com/SLP-DEV1/PenX/-/releases/v0.4.7")
        with patch.object(updates, "check_update", return_value=release), \
             patch.object(updates, "installed_mode", return_value=True), \
             patch.object(updates.os, "name", "nt"), \
             patch("builtins.input", return_value="n"), \
             patch.object(updates, "download_verified_installer") as download, \
             patch.object(updates.subprocess, "Popen") as proc:
            self.assertFalse(updates.update_interactive())
            download.assert_not_called()
            proc.assert_not_called()

    def test_startup_notice_never_checks_in_portable_mode(self):
        with patch.object(updates, "installed_mode", return_value=False), \
             patch.object(updates, "check_update") as check:
            updates.startup_notice()
            check.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
