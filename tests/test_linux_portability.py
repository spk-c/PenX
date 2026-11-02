"""Linux cross-platform contract tests; no network, installation, or scanning."""
from __future__ import annotations

import contextlib
import importlib.util
import io
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from penx_app import app_paths
from penx_app.setup import first_run_setup
from penx_app.scanners import tools
from penx_app.scanners import native_web_scanners


class LinuxPortabilityTests(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "Linux-only XDG path test")
    def test_xdg_user_data_location(self):
        with tempfile.TemporaryDirectory() as temp:
            with patch.dict(os.environ, {"XDG_DATA_HOME": temp}):
                self.assertEqual(app_paths.user_data_base(), Path(temp))
            with patch.dict(os.environ, {"XDG_DATA_HOME": ""}):
                self.assertEqual(app_paths.user_data_base(),
                                 Path.home() / ".local" / "share")

    def test_linux_scanner_status_has_no_npcap_and_finds_distro_bins(self):
        def runtime(name):
            return "/usr/bin/" + name
        with patch.object(first_run_setup, "is_windows", return_value=False), \
             patch.object(first_run_setup, "find_nmap", return_value="/usr/bin/nmap"), \
             patch.object(first_run_setup, "find_runtime", side_effect=runtime), \
             patch.object(first_run_setup, "find_native", return_value=None), \
             patch.object(first_run_setup.shutil, "which", side_effect=lambda name: f"/usr/bin/{name}"):
            status = first_run_setup.scanner_status()
        self.assertTrue(status["WhatWeb"])
        self.assertTrue(status["Nikto"])
        self.assertTrue(status["Perl"])
        self.assertNotIn("Npcap", status)
        self.assertNotIn("Strawberry Perl", status)

    def test_linux_setup_does_not_invoke_windows_installer(self):
        with patch.object(first_run_setup, "is_windows", return_value=False), \
             patch.object(first_run_setup, "ensure_private_env") as config, \
             patch.object(first_run_setup, "print_status") as status, \
             patch.object(first_run_setup.install_scanners_windows, "main") as win:
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(first_run_setup.run_setup(force=True), 0)
            config.assert_called_once()
            status.assert_called_once()
            win.assert_not_called()

    def test_nikto_on_path_does_not_require_vendored_windows_script(self):
        with patch.object(tools, "NIKTO_PATH", ""), \
             patch.object(tools, "_executable", return_value="/usr/bin/nikto"), \
             patch.object(tools, "_run_external", return_value="Nikto scan done") as run:
            result = tools.run_nikto("https://example.org")
        self.assertIn("Nikto scan done", str(result))
        self.assertEqual(run.call_args.args[0][0], "/usr/bin/nikto")

    @unittest.skipIf(os.name == "nt", "Linux-only executable check")
    def test_non_executable_vendor_binary_is_not_used(self):
        with tempfile.TemporaryDirectory() as temp:
            binary = Path(temp) / "ffuf"
            binary.write_text("test", encoding="utf-8")
            with patch.object(native_web_scanners, "APP_ROOT", Path(temp)), \
                 patch.dict(os.environ, {"PENX_FFUF_PATH": str(binary)}):
                self.assertIsNone(native_web_scanners.find_native("ffuf"))
            binary.chmod(0o700)
            with patch.dict(os.environ, {"PENX_FFUF_PATH": str(binary)}):
                self.assertEqual(native_web_scanners.find_native("ffuf"), str(binary))

    def test_linux_packaging_sources_are_present(self):
        for filename in ("LINUX.md", "install-linux.sh",
                         "scripts/build_linux.py",
                         "packaging/linux/build_packages.py"):
            self.assertTrue((ROOT / filename).is_file(), filename)


if __name__ == "__main__":
    unittest.main()
