"""Offline regression tests for Back navigation in PenX's terminal menus."""
from __future__ import annotations

import os
import unittest
from unittest.mock import patch

import penx
from penx_app.scanners import tools
from penx_app.cli import assessment_ui
from penx_app.cli.cli_navigation import is_back, show_back, navigation_input, _read_chars, _read_windows
from penx_app.reporting.export import export_menu


class NavigationTests(unittest.TestCase):
    def test_back_aliases_are_explicit(self):
        for value in ("0", "b", "B", "back", " BACK ", "\x1b"):
            self.assertTrue(is_back(value))
        for value in ("", "example.test", "10", "1", "not back"):
            self.assertFalse(is_back(value))

    def test_back_menu_entry_is_clean_and_consistent(self):
        from contextlib import redirect_stdout
        from io import StringIO

        output = StringIO()
        with redirect_stdout(output):
            show_back()
        self.assertEqual(
            output.getvalue(),
            "  \x1b[92m[Esc]\x1b[0m  Back to main menu\n",
        )

    def test_failed_scan_requires_acknowledgement_before_menu_redraw(self):
        from penx_app.application.scan_outcome import ScanOutcome
        with patch("penx._execute_scan", return_value=ScanOutcome(False, True, "recon_failed")), \
             patch("penx.banner", side_effect=[None, KeyboardInterrupt]), \
             patch("penx.prompt", return_value="1"), \
             patch("builtins.input", return_value="") as pause:
            with self.assertRaises(KeyboardInterrupt):
                penx._main_menu_loop()
        pause.assert_called_once()
        self.assertIn("return to main menu", pause.call_args.args[0])

    def test_new_scan_shows_back_only_once(self):
        from contextlib import redirect_stdout
        from io import StringIO

        output = StringIO()
        with patch("penx.prompt", return_value="back") as target_prompt, redirect_stdout(output):
            self.assertIs(penx.new_scan(), False)
        target_prompt.assert_called_once_with("[?] Enter target IP or domain: ", navigation=True)
        self.assertEqual(output.getvalue().count("Back to main menu"), 1)

    def test_escape_key_returns_back_immediately_without_enter(self):
        """Raw Esc alone must cancel; no Enter or other keys are required."""
        from unittest.mock import Mock
        read = Mock(side_effect=["\x1b"])
        self.assertEqual(_read_chars("Target: ", read), "back")
        read.assert_called_once()

    def test_keyboard_editing_and_extended_keys(self):
        from unittest.mock import Mock
        self.assertEqual(
            _read_chars("Target: ", Mock(side_effect=["t", "e", "x", "\b", "s", "t", "\r"])),
            "test",
        )
        # Windows arrows emit a prefix and a second scan code; never navigate Back.
        self.assertEqual(
            _read_chars("Select: ", Mock(side_effect=["\xe0", "H", "1", "\r"])),
            "1",
        )
        with self.assertRaises(KeyboardInterrupt):
            _read_chars("Select: ", Mock(side_effect=["\x03"]))

    def test_windows_console_escape_routes_to_native_key_reader(self):
        import sys
        import types
        from unittest.mock import Mock
        fake_msvcrt = types.SimpleNamespace(getwch=Mock(side_effect=["\x1b"]))
        with patch.dict(sys.modules, {"msvcrt": fake_msvcrt}):
            self.assertEqual(_read_windows("Select: "), "back")
        fake_msvcrt.getwch.assert_called_once()

    def test_noninteractive_input_remains_backward_compatible(self):
        import types
        fake_sys = types.SimpleNamespace(
            stdin=types.SimpleNamespace(isatty=lambda: False),
            stdout=types.SimpleNamespace(isatty=lambda: False),
        )
        with patch("penx_app.cli.cli_navigation.sys", fake_sys), \
             patch("builtins.input", return_value="0") as standard_input:
            self.assertEqual(navigation_input("Select: "), "0")
            standard_input.assert_called_once_with("Select: ")

    def test_new_scan_back_skips_auth_history_scanners_and_database(self):
        for selection in ("0", "b", "back"):
            with self.subTest(selection=selection), \
                 patch("penx.prompt", return_value=selection), \
                 patch("penx.llm_auth_preflight", side_effect=AssertionError("auth queried")), \
                 patch("penx.get_all_history", side_effect=AssertionError("history queried")), \
                 patch("penx.interactive_tool_run", side_effect=AssertionError("scanner started")), \
                 patch("penx.create_session", side_effect=AssertionError("session created")):
                self.assertIs(penx.new_scan(), False)
                self.assertIs(penx.new_scan(passive_only=True), False)

    def test_main_menu_reappears_without_extra_pause_after_back(self):
        for selected_menu, return_choice in (("1", "0"), ("1", "back")):
            with self.subTest(menu=selected_menu), \
                 patch("penx.banner") as banner, \
                 patch("penx.llm_auth_preflight", side_effect=AssertionError("auth queried")), \
                 patch("penx.create_session", side_effect=AssertionError("session created")), \
                 patch("builtins.input", side_effect=[selected_menu, return_choice, "8"]):
                with self.assertRaises(SystemExit) as exit_status:
                    penx.main_menu()
                self.assertEqual(exit_status.exception.code, 0)
                self.assertEqual(banner.call_count, 2)

    def test_scanner_selection_back_skips_all_tools(self):
        def forbidden(_target):
            raise AssertionError("A scanner should never run after Back")
        with patch.dict(tools.TOOLS_MENU, {"1": ("nmap", forbidden)}, clear=True):
            for selection in ("b", "BACK", "1 back", "1 0", "0 1"):
                with self.subTest(selection=selection), \
                     patch("builtins.input", return_value=selection):
                    self.assertIsNone(tools.interactive_tool_run("example.test"))

    def test_zero_selects_passive_only_without_active_scanners(self):
        def forbidden(_target):
            raise AssertionError("Must not run active tools for passive menu [0]")
        with patch.dict(tools.TOOLS_MENU, {"1": ("nmap", forbidden)}, clear=True), \
             patch("builtins.input", return_value="0"):
            self.assertIs(tools.interactive_tool_run("example.test"),
                          tools.ReconChoice.PASSIVE_ONLY)

    def test_zero_routes_to_passive_recon_and_disables_llm_tools(self):
        passive_result = '[RDAP]\n{"name": "example.test"}'
        with patch("penx.prompt", return_value="example.test"), \
             patch("penx.llm_auth_preflight", return_value=True), \
             patch("penx.get_all_history", return_value=[]), \
             patch("penx.interactive_tool_run",
                   return_value=tools.ReconChoice.PASSIVE_ONLY), \
             patch("penx_app.scanners.passive_recon.passive_recon", return_value=passive_result) as passive, \
             patch("penx.analyse_target", side_effect=RuntimeError("offline test")) as analyse, \
             patch("penx.create_session", return_value=42), \
             patch("penx.preserve_failed_recon", return_value="test.txt"), \
             patch("penx.delete_full_session"):
            penx.new_scan()
        passive.assert_called_once_with("example.test")
        analyse.assert_called_once_with("example.test", passive_result, passive_only=True)

    def test_back_from_scanner_picker_leaves_no_database_record(self):
        for selection in ("b", "back"):
            with self.subTest(selection=selection), \
                 patch("penx.prompt", return_value="example.test"), \
                 patch("penx.llm_auth_preflight", return_value=True), \
                 patch("penx.get_all_history", return_value=[]), \
                 patch("builtins.input", return_value=selection), \
                 patch("penx.create_session", side_effect=AssertionError("session created")), \
                 patch("penx.analyse_target", side_effect=AssertionError("LLM called")):
                self.assertIs(penx.new_scan(), False)

    def test_history_and_reports_accept_back(self):
        with patch("penx.get_all_history", return_value=[
            (21, "example.test", "2026-10-14", "active")
        ]), patch("penx.prompt", return_value="0"), \
             patch("penx.get_session", side_effect=AssertionError("record opened")):
            penx.view_history()
        data = {"history": (21, "example.test", "2026-10-14", "active")}
        for choice in ("0", "b", "back", "4"):
            with self.subTest(choice=choice), \
                 patch("builtins.input", return_value=choice), \
                 patch("penx_app.reporting.export.os.makedirs", side_effect=AssertionError("created directory")), \
                 patch("penx_app.reporting.export.export_pdf", side_effect=AssertionError("generated PDF")), \
                 patch("penx_app.reporting.export.export_html", side_effect=AssertionError("generated HTML")):
                export_menu(data)

    def test_edit_menu_back_does_not_toggle_live_setting(self):
        for choice in ("12", "0", "b", "back"):
            with self.subTest(choice=choice), \
                 patch("penx.prompt", return_value=choice) as prompt, \
                 patch("penx.new_scan", side_effect=AssertionError("wrong menu handler")), \
                 patch.dict(os.environ, {"PENX_LIVE_OUTPUT": "1"}):
                penx.edit_delete_menu(21)
                self.assertEqual(os.environ["PENX_LIVE_OUTPUT"], "1")
                prompt.assert_called_once()

    def test_edit_menu_correction_actions_reachable_again(self):
        correction = (5, 21, 7, "verified", "orig", "corrected", "reason", "time")
        with patch("penx.get_corrections", return_value=[correction]), \
             patch("penx.prompt", side_effect=["9", "5", "reason", "updated", "12"]), \
             patch("penx.edit_correction") as edit, \
             patch("penx.new_scan", side_effect=AssertionError("wrong handler")):
            penx.edit_delete_menu(21)
            edit.assert_called_once_with(5, "reason", "updated", sl_no=21)
        with patch("penx.get_corrections", return_value=[correction]), \
             patch("penx.prompt", side_effect=["10", "5", "12"]), \
             patch("penx.confirm", return_value=True), \
             patch("penx.delete_correction") as delete, \
             patch("penx.new_scan", side_effect=AssertionError("wrong handler")):
            penx.edit_delete_menu(21)
            delete.assert_called_once_with(5, sl_no=21)
        with patch("penx.prompt", return_value="11"), \
             patch("penx.confirm", return_value=True), \
             patch("penx.delete_full_session") as delete_full:
            penx.edit_delete_menu(21)
            delete_full.assert_called_once_with(21)

    def test_risk_and_trend_selectors_accept_back(self):
        rows = [(1, "example.test", "2026-10-13", "active"),
                (2, "example.test", "2026-10-14", "active")]
        with patch("penx_app.cli.assessment_ui.get_all_history", return_value=rows), \
             patch("builtins.input", return_value="0"), \
             patch("penx_app.cli.assessment_ui.matching_history", side_effect=AssertionError("continued")):
            assessment_ui.compare_menu()
        with patch("penx_app.cli.assessment_ui.get_all_history", return_value=rows), \
             patch("builtins.input", return_value="back"), \
             patch("penx_app.cli.assessment_ui.assessment_for_session", side_effect=AssertionError("continued")):
            assessment_ui.risk_menu()


if __name__ == "__main__":
    unittest.main(verbosity=2)
