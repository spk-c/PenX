"""Offline regression tests for the portable EXE first-run wizard.

Tests mock all scanners, installers and user input: no downloads or UAC.
"""
from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from penx_app.setup import first_run_setup as first_run


class FirstRunSetupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.marker = self.root / "data" / ".scanner-setup-offered"
        a = patch.object(first_run, "APP_ROOT", self.root)
        b = patch.object(first_run, "FIRST_RUN_MARKER", self.marker)
        c = patch.object(first_run, "is_windows", return_value=True)
        d = patch.object(first_run.sys, "frozen", True, create=True)
        for ctx in (a, b, c, d):
            ctx.start()
            self.addCleanup(ctx.stop)

    def test_env_is_copied_without_overwriting_existing_config(self):
        (self.root / ".env.example").write_text("PENX_MODEL=sample\n", encoding="utf-8")
        first_run.ensure_private_env()
        self.assertEqual((self.root / ".env").read_text(encoding="utf-8"), "PENX_MODEL=sample\n")
        (self.root / ".env").write_text("PENX_MODEL=private\n", encoding="utf-8")
        first_run.ensure_private_env()
        self.assertEqual((self.root / ".env").read_text(encoding="utf-8"), "PENX_MODEL=private\n")

    def test_first_launch_decline_is_recorded_without_installing(self):
        with patch.object(first_run, "missing_scanners", return_value=["Nmap", "Npcap"]), \
             patch("builtins.input", return_value="n"), \
             patch.object(first_run.install_scanners_windows, "main") as installer:
            self.assertEqual(first_run.run_setup(), 0)
            self.assertTrue(self.marker.is_file())
            self.assertEqual(first_run.run_setup(), 0)
            installer.assert_not_called()

    def test_first_launch_accept_runs_existing_installer_exactly_once(self):
        with patch.object(first_run, "missing_scanners", side_effect=[["WhatWeb", "Ruby"], []]), \
             patch("builtins.input", return_value="y"), \
             patch.object(first_run.install_scanners_windows, "main", return_value=0) as installer:
            self.assertEqual(first_run.run_setup(), 0)
            installer.assert_called_once_with([])
            self.assertTrue(self.marker.is_file())

    def test_explicit_setup_retries_even_after_skipping_first_launch(self):
        first_run.mark_offered()
        with patch.object(first_run, "missing_scanners", side_effect=[["Nikto"], []]), \
             patch("builtins.input", return_value="yes"), \
             patch.object(first_run.install_scanners_windows, "main", return_value=0) as installer:
            self.assertEqual(first_run.run_setup(force=True), 0)
            installer.assert_called_once_with([])

    def test_explicit_setup_reports_incomplete_install(self):
        with patch.object(first_run, "missing_scanners", return_value=["Nmap"]), \
             patch("builtins.input", return_value="y"), \
             patch.object(first_run.install_scanners_windows, "main", return_value=1):
            self.assertEqual(first_run.run_setup(force=True), 1)
            self.assertTrue(self.marker.is_file())

    def test_installer_failure_never_blocks_normal_first_launch(self):
        with patch.object(first_run, "missing_scanners", return_value=["Nmap"]), \
             patch("builtins.input", return_value="y"), \
             patch.object(first_run.install_scanners_windows, "main", side_effect=OSError("offline")):
            self.assertEqual(first_run.run_setup(), 0)

    def test_all_components_present_never_offers_install(self):
        with patch.object(first_run, "missing_scanners", return_value=[]), \
             patch("builtins.input") as consent, \
             patch.object(first_run.install_scanners_windows, "main") as installer:
            self.assertEqual(first_run.run_setup(), 0)
            consent.assert_not_called()
            installer.assert_not_called()
            self.assertTrue(self.marker.is_file())

    def test_non_windows_platform_never_runs_installer(self):
        with patch.object(first_run, "is_windows", return_value=False), \
             patch.object(first_run.install_scanners_windows, "main") as installer:
            self.assertEqual(first_run.run_setup(), 0)
            self.assertEqual(first_run.run_setup(force=True), 2)
            installer.assert_not_called()

    def test_source_mode_does_not_offer_first_run_installer(self):
        with patch.object(first_run.sys, "frozen", False, create=True), \
             patch.object(first_run, "missing_scanners") as missing:
            self.assertEqual(first_run.run_setup(), 0)
            missing.assert_not_called()

    def test_subfinder_and_katana_are_checked_without_executing(self):
        with patch.object(first_run, "find_native", side_effect=lambda n: None if n in ("subfinder", "katana") else "scanner.exe"), \
             patch.object(first_run, "find_nmap", return_value="nmap.exe"), \
             patch.object(first_run, "find_runtime", return_value="runtime.exe"), \
             patch.object(first_run, "npcap_present", return_value=True), \
             patch.object(first_run, "NIKTO_PATH", self.root / "nikto.pl"), \
             patch.object(first_run, "WHATWEB_PATH", self.root / "whatweb"):
            status = first_run.scanner_status()
        self.assertFalse(status["Subfinder"])
        self.assertFalse(status["Katana"])
        self.assertTrue(status["Nuclei"])
        self.assertIn("Subfinder", status)
        self.assertIn("Katana", status)

    def test_setup_status_does_not_install_or_prompt(self):
        states = {"Nmap": True, "Npcap": False, "Ruby": True}
        with patch.object(first_run, "scanner_status", return_value=states), \
             patch("builtins.print") as output, \
             patch("builtins.input") as prompt, \
             patch.object(first_run.install_scanners_windows, "main") as installer:
            first_run.print_status()
            self.assertTrue(any("[MISSING] Npcap" in x.args[0] for x in output.call_args_list))
            prompt.assert_not_called()
            installer.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
