"""PX-190: package manifest integrity gates must work with Python -O.

Synthetic, local filesystem fixtures only: no installs, network or publication.
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

    def check(self, optimized=False):
        command = [sys.executable]
        if optimized:
            command.append("-O")
        command.append(str(self.script))
        return subprocess.run(
            command, capture_output=True, text=True,
            cwd=self.root, timeout=15, check=False,
        )

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


if __name__ == "__main__":
    unittest.main()
