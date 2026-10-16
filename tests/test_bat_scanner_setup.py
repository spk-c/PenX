"""Static Windows BAT setup invariants; safe to run on Linux CI."""
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class BatchSetupContractTests(unittest.TestCase):
    def test_install_windows_uses_unified_scanner_installer(self):
        source = (ROOT / "install-windows.bat").read_text(encoding="utf-8")
        self.assertIn('install_scanners_windows.py', source)
        self.assertIn('set "scanner_result=%errorlevel%"', source)
        self.assertIn('if not "%scanner_result%"=="0"', source)
        self.assertIn('exit /b 2', source)
        for tool in ("Nmap/Npcap", "WhatWeb", "Nikto", "Nuclei", "httpx", "ffuf"):
            self.assertIn(tool, source)

    def test_retry_bat_uses_same_installer_and_propagates_result(self):
        source = (ROOT / "install-scanners.bat").read_text(encoding="utf-8")
        self.assertIn('install_scanners_windows.py', source)
        self.assertIn('set "result=%errorlevel%"', source)
        self.assertIn('exit /b %result%', source)

    def test_start_bat_does_not_implicitly_download_anything(self):
        source = (ROOT / "start-windows.bat").read_text(encoding="utf-8")
        self.assertNotIn('install_scanners_windows.py', source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
