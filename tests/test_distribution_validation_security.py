"""PX-005/PX-190: package manifest integrity gates must work with Python -O.

Synthetic, local filesystem fixtures only: no installs, network or publication.

Each check branch in scripts/validate_distributions.py has a dedicated negative
fixture: tampering with any archive URL, hash, package ID/version, manifest type,
installer kind, scope, or product code must be rejected with a specific message.
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

    def test_optimized_python_rejects_changed_scoop_hash(self):
        manifest = json.loads(self.scoop_path.read_text(encoding="utf-8"))
        manifest["architecture"]["64bit"]["hash"] = "0" * 64
        self.scoop_path.write_text(json.dumps(manifest), encoding="utf-8")
        result = self.check(optimized=True)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("Scoop archive SHA-256 mismatch", result.stderr)

    def test_optimized_python_rejects_changed_winget_hash(self):
        content = self.winget_path.read_text(encoding="utf-8")
        content = content.replace(
            "A99922E88A3A3C83B12BF017B7BAE3EBA68C8313BD547D58087AA53C383E602A",
            "0" * 64,
        )
        self.winget_path.write_text(content, encoding="utf-8")
        result = self.check(optimized=True)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("WinGet installer SHA-256 mismatch", result.stderr)

    def test_optimized_python_rejects_changed_historical_winget_hash(self):
        historical = self.winget_path.parent.parent / "0.6.0" / self.winget_path.name
        content = historical.read_text(encoding="utf-8")
        tampered = content.replace(
            "2560CDC2B0FF239F148DA1508F07243AF907C90FBC7516E3395C7F5BCAD03F5F",
            "0" * 64,
        )
        self.assertNotEqual(tampered, content)
        historical.write_text(tampered, encoding="utf-8")
        result = self.check(optimized=True)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("WinGet installer SHA-256 mismatch", result.stderr)

    def test_optimized_python_rejects_missing_historical_winget_folder(self):
        shutil.rmtree(self.winget_path.parent.parent / "0.6.0")
        result = self.check(optimized=True)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("WinGet version folders", result.stderr)

    def test_optimized_python_rejects_unpinned_winget_folder(self):
        shutil.copytree(self.winget_path.parent, self.winget_path.parent.parent / "9.9.9")
        result = self.check(optimized=True)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("WinGet version folders", result.stderr)

    def test_optimized_python_rejects_portable_winget_installer(self):
        content = self.winget_path.read_text(encoding="utf-8")
        content = content.replace("InstallerType: inno", "InstallerType: portable")
        self.winget_path.write_text(content, encoding="utf-8")
        result = self.check(optimized=True)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("WinGet installer type must be inno", result.stderr)

    def test_optimized_python_rejects_invalid_scoop_sha256(self):
        manifest = self._scoop()
        manifest["architecture"]["64bit"]["hash"] = "not-a-sha256"
        self._write_scoop(manifest)
        result = self.check(optimized=True)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("Scoop archive SHA-256 mismatch", result.stderr)

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
        self.assertIn("WinGet version folders", result.stderr)

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
            "InstallerType: inno",
            "InstallerType: msi",
        )
        result = self.check(optimized=True)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("WinGet installer type must be inno", result.stderr)

    def test_optimized_python_rejects_wrong_installer_scope(self):
        self._patch_winget(
            self.winget_path,
            "Scope: user",
            "Scope: machine",
        )
        result = self.check(optimized=True)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("WinGet installer scope must be user", result.stderr)

    def test_optimized_python_rejects_wrong_installer_url(self):
        self._patch_winget(
            self.winget_path,
            "InstallerUrl: https://github.com/spk-c/PenX/releases/download/v0.6.1/PenX-Setup-x64.exe",
            "InstallerUrl: https://example.invalid/untrusted-penx.zip",
        )
        result = self.check(optimized=True)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("WinGet installer URL/version mismatch", result.stderr)

    def test_optimized_python_rejects_missing_scoop_persist_vendor(self):
        manifest = self._scoop()
        manifest["persist"].remove("PenX\\vendor")
        self._write_scoop(manifest)
        result = self.check(optimized=True)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("Scoop must persist downloaded tools", result.stderr)

    def test_optimized_python_rejects_non_list_scoop_persist(self):
        manifest = self._scoop()
        manifest["persist"] = " ".join(manifest["persist"])
        self._write_scoop(manifest)
        result = self.check(optimized=True)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("Scoop persist must be a list", result.stderr)

    def test_optimized_python_rejects_duplicate_scoop_keys(self):
        content = self.scoop_path.read_text(encoding="utf-8")
        self.scoop_path.write_text(content.replace('"version": "0.6.1",',
            '"version": "0.0.0", "version": "0.6.1",'), encoding="utf-8")
        result = self.check(optimized=True)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("Duplicate Scoop manifest key", result.stderr)

    def test_optimized_python_rejects_unpinned_scoop_version(self):
        manifest = self._scoop()
        manifest["version"] = "0.0.0"
        self._write_scoop(manifest)
        result = self.check(optimized=True)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("Unpinned Scoop version", result.stderr)

    def test_optimized_python_rejects_unpinned_scoop_architecture(self):
        manifest = self._scoop()
        manifest["architecture"]["32bit"] = manifest["architecture"]["64bit"]
        self._write_scoop(manifest)
        result = self.check(optimized=True)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("Scoop architecture must be 64bit only", result.stderr)

    def test_optimized_python_rejects_wrong_winget_architecture(self):
        self._patch_winget(self.winget_path, "Architecture: x64", "Architecture: x86")
        result = self.check(optimized=True)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("WinGet installer architecture must be x64", result.stderr)

    def test_optimized_python_rejects_wrong_product_code(self):
        self._patch_winget(
            self.winget_path,
            "ProductCode: '{FCF9D8F6-64E9-4783-8E7F-9106E194C841}_is1'",
            "ProductCode: wrong",
        )
        result = self.check(optimized=True)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("WinGet installer product code mismatch", result.stderr)


if __name__ == "__main__":
    unittest.main()
