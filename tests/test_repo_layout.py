"""Ensure the public entrypoints work after the source/test folder split."""
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


class RepositoryLayoutTests(unittest.TestCase):
    def test_layout_keeps_public_entrypoint_and_source(self):
        self.assertTrue((ROOT / "penx.py").is_file())
        self.assertTrue((ROOT / "src" / "llm.py").is_file())
        self.assertTrue((ROOT / "src" / "app_paths.py").is_file())
        from app_paths import APP_ROOT
        self.assertEqual(APP_ROOT, ROOT)

    def test_version_command_from_repository_root(self):
        proc = subprocess.run([sys.executable, str(ROOT / "penx.py"), "--version"],
                              cwd=ROOT, text=True, capture_output=True, timeout=30)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("PenX Windows", proc.stdout)

    def test_utility_entrypoint_imports(self):
        proc = subprocess.run([sys.executable, str(ROOT / "cve_quality.py"), "--help"],
                              cwd=ROOT, text=True, capture_output=True, timeout=30)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        proc = subprocess.run([sys.executable, str(ROOT / "install_scanners_windows.py"), "--help"],
                              cwd=ROOT, text=True, capture_output=True, timeout=30)
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_legacy_shims_retired_except_public_entrypoints(self):
        # Only the public/pinned compatibility shims remain as top-level
        # src/*.py modules; every other legacy shim has been retired.
        from scripts import import_inventory
        self.assertEqual(import_inventory.KEPT, frozenset({"llm", "app_paths"}))
        shims_on_disk = {p.stem for p in (ROOT / "src").glob("*.py")}
        self.assertEqual(shims_on_disk, set(import_inventory.KEPT))
        # REMOVED and KEPT partition the known legacy shim names exactly.
        legacy_names = set(import_inventory.LEGACY)
        self.assertEqual(import_inventory.REMOVED | import_inventory.KEPT, legacy_names)
        self.assertFalse(import_inventory.REMOVED & import_inventory.KEPT)

    def test_import_inventory_reports_no_retired_consumers(self):
        from scripts import import_inventory
        self.assertEqual(import_inventory.violations(ROOT), [])
        self.assertEqual(import_inventory.check(ROOT), 0)
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "import_inventory.py"), "--check"],
            cwd=ROOT, text=True, capture_output=True, timeout=120)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("OK: no consumers reference a retired legacy name.", proc.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
