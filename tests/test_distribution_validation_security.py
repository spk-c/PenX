"""PX-005/PX-190: package manifest integrity gates must work with Python -O.

Synthetic, local filesystem fixtures only: no installs, network or publication.

Each check branch in scripts/validate_distributions.py has a dedicated negative
fixture: tampering with any archive URL, hash, package ID/version, manifest type,
installer kind, or portable path/alias must be rejected with a specific message.
"""
from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class DistributionValidationSecurityTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="penx-distribution-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / "scripts").mkdir()
        self.script = self.root / "scripts" / "validate_distributions.py"
        shutil.copy2(ROOT / "scripts" / "validate_distributions.py", self.script)
        shutil.copytree(ROOT / "packaging", self.root / "packaging")
        self.scoop_path = self.root / "packaging" / "scoop" / "penx.json"
        self.winget_path = (
            self.root / "packaging" / "winget" / "manifests" / "s"
            / "SLP-DEV1" / "PenX" / "0.6.1"
            / "SLP-DEV1.PenX.installer.yaml"
        )
        self.winget_version_dir = self.winget_path.parent
        self.winget_root_path = self.winget_version_dir / "SLP-DEV1.PenX.yaml"
        self.winget_locale_path = (
            self.winget_version_dir / "SLP-DEV1.PenX.locale.en-US.yaml"
        )

    def check(self, optimized=False):
        command = [sys.executable]
        if optimized:
            command.append("-O")
        command.append(str(self.script))
        return subprocess.run(
            command, capture_output=True, text=True,
            cwd=self.root, timeout=15, check=False,
        )

    def _scoop(self):
        return json.loads(self.scoop_path.read_text(encoding="utf-8"))

    def _write_scoop(self, manifest):
        self.scoop_path.write_text(json.dumps(manifest), encoding="utf-8")

    def _winget_text(self, path):
        return path.read_text(encoding="utf-8")

    def _patch_winget(self, path, old, new):
        text = self._winget_text(path)
        self.assertEqual(text.count(old), 1,
                         "expected exactly one %r in %s" % (old, path.name))
        path.write_text(text.replace(old, new), encoding="utf-8")

    def test_valid_official_drafts_pass_even_when_optimized(self):
        self.assertEqual(self.check().returncode, 0)
        self.assertEqual(self.check(optimized=True).returncode, 0)

    def test_optimized_python_rejects_tampered_archive_url(self):
        manifest = json.loads(self.scoop_path.read_text(encoding="utf-8"))
        manifest["architecture"]["64bit"]["url"] = (
            "https://example.invalid/untrusted-penx.zip"
        )
        self.scoop_path.write_text(json.dumps(manifest), encoding="utf-8")
        result = self.check(optimized=True)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("Scoop archive URL/version mismatch", result.stderr)

    def test_optimized_python_rejects_unsafe_persist_change(self):
        manifest = json.loads(self.scoop_path.read_text(encoding="utf-8"))
        manifest["persist"].remove("PenX\\data")
        self.scoop_path.write_text(json.dumps(manifest), encoding="utf-8")
        result = self.check(optimized=True)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("persist scan database", result.stderr)

    def test_optimized_python_rejects_changed_winget_hash(self):
        content = self.winget_path.read_text(encoding="utf-8")
        content = content.replace(
            "5D37FBC3D50E524D8335CB9B3B8CA5C8191D4E6216FB574BA009F2454D626E44",
            "0" * 64,
        )
        self.winget_path.write_text(content, encoding="utf-8")
        result = self.check(optimized=True)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("WinGet/Scoop SHA-256 mismatch", result.stderr)

    def test_optimized_python_rejects_invalid_scoop_sha256(self):
        manifest = self._scoop()
        manifest["architecture"]["64bit"]["hash"] = "not-a-sha256"
        self._write_scoop(manifest)
        result = self.check(optimized=True)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("Invalid Scoop archive SHA-256", result.stderr)

    def test_optimized_python_rejects_missing_scoop_command_shim(self):
        manifest = self._scoop()
        manifest["bin"] = []
        self._write_scoop(manifest)
        result = self.check(optimized=True)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("Missing Scoop command shim", result.stderr)

    def test_optimized_python_rejects_missing_scoop_persist_configuration(self):
        manifest = self._scoop()
        manifest["persist"].remove("PenX\\.env")
        self._write_scoop(manifest)
        result = self.check(optimized=True)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("Scoop must persist configuration", result.stderr)

    def test_optimized_python_rejects_missing_scoop_persist_reports(self):
        manifest = self._scoop()
        manifest["persist"].remove("PenX\\reports")
        self._write_scoop(manifest)
        result = self.check(optimized=True)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("Scoop must persist reports", result.stderr)

    def test_optimized_python_rejects_missing_winget_version_folder(self):
        shutil.rmtree(self.winget_version_dir)
        result = self.check(optimized=True)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("Missing WinGet version folder", result.stderr)

    def test_optimized_python_rejects_missing_winget_manifest_file(self):
        self.winget_root_path.unlink()
        result = self.check(optimized=True)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("Missing WinGet manifest", result.stderr)

    def test_optimized_python_rejects_wrong_package_identifier(self):
        self._patch_winget(
            self.winget_root_path,
            "PackageIdentifier: SLP-DEV1.PenX",
            "PackageIdentifier: SLP-DEV1.Other",
        )
        result = self.check(optimized=True)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("Unexpected package ID", result.stderr)

    def test_optimized_python_rejects_wrong_package_version(self):
        self._patch_winget(
            self.winget_root_path,
            "PackageVersion: 0.6.1",
            "PackageVersion: 0.9.9",
        )
        result = self.check(optimized=True)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("Package version mismatch", result.stderr)

    def test_optimized_python_rejects_wrong_version_manifest_type(self):
        self._patch_winget(
            self.winget_root_path,
            "ManifestType: version",
            "ManifestType: installer",
        )
        result = self.check(optimized=True)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("Invalid WinGet version manifest type", result.stderr)

    def test_optimized_python_rejects_wrong_installer_manifest_type(self):
        self._patch_winget(
            self.winget_path,
            "ManifestType: installer",
            "ManifestType: version",
        )
        result = self.check(optimized=True)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("Invalid WinGet installer manifest type", result.stderr)

    def test_optimized_python_rejects_wrong_locale_manifest_type(self):
        self._patch_winget(
            self.winget_locale_path,
            "ManifestType: defaultLocale",
            "ManifestType: version",
        )
        result = self.check(optimized=True)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("Invalid WinGet locale manifest type", result.stderr)

    def test_optimized_python_rejects_wrong_installer_type(self):
        self._patch_winget(
            self.winget_path,
            "InstallerType: zip",
            "InstallerType: msi",
        )
        result = self.check(optimized=True)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("WinGet installer type must be zip", result.stderr)

    def test_optimized_python_rejects_wrong_nested_installer_type(self):
        self._patch_winget(
            self.winget_path,
            "NestedInstallerType: portable",
            "NestedInstallerType: fixed",
        )
        result = self.check(optimized=True)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("WinGet nested installer type must be portable", result.stderr)

    def test_optimized_python_rejects_wrong_installer_url(self):
        self._patch_winget(
            self.winget_path,
            "InstallerUrl: https://github.com/spk-c/PenX/releases/download/v0.6.1/PenX-Windows-x64.zip",
            "InstallerUrl: https://example.invalid/untrusted-penx.zip",
        )
        result = self.check(optimized=True)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("WinGet installer URL/version mismatch", result.stderr)

    def test_optimized_python_rejects_wrong_relative_file_path(self):
        self._patch_winget(
            self.winget_path,
            "RelativeFilePath: PenX/PenX.exe",
            "RelativeFilePath: PenX/other.exe",
        )
        result = self.check(optimized=True)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("WinGet portable executable path mismatch", result.stderr)

    def test_optimized_python_rejects_wrong_portable_command_alias(self):
        self._patch_winget(
            self.winget_path,
            "PortableCommandAlias: penx",
            "PortableCommandAlias: pen",
        )
        result = self.check(optimized=True)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("WinGet portable command alias mismatch", result.stderr)


if __name__ == "__main__":
    unittest.main()
