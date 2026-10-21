"""Check installed/uninstalled Windows CI smoke boundaries without running setup."""
from pathlib import Path
import unittest

CI = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "ci.yml"


class WindowsUninstallCIContractTests(unittest.TestCase):
    def test_per_user_installer_smoke_includes_actual_uninstaller(self):
        workflow = CI.read_text(encoding="utf-8")
        self.assertIn("Windows installer build and installed EXE smoke test (manual)", workflow)
        self.assertIn("Join-Path $smoke \"unins000.exe\"", workflow)
        self.assertIn("Start-Process -FilePath $uninstaller", workflow)
        self.assertIn("/VERYSILENT", workflow)
        self.assertIn("Uninstaller left the installed PenX.exe behind", workflow)

    def test_uninstall_must_preserve_user_data_and_cleanup_only_test_marker(self):
        workflow = CI.read_text(encoding="utf-8")
        self.assertIn('Join-Path $env:LOCALAPPDATA "PenX"', workflow)
        self.assertIn("ci-uninstall-preserve-$env:GITHUB_RUN_ID.marker", workflow)
        self.assertIn("Uninstaller removed the per-user PenX data marker", workflow)
        self.assertIn("Remove-Item -LiteralPath $sentinel -Force", workflow)
        self.assertNotIn("Remove-Item -LiteralPath $userData -Recurse", workflow)


if __name__ == "__main__":
    unittest.main()
