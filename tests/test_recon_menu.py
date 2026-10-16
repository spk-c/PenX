"""Offline regression tests for the shared recon choice menu and the
recon-only main-menu step (no session, no assessment, no model query)."""
from __future__ import annotations

import unittest
from unittest.mock import patch

import penx
from penx_app.scanners import tools


class ReconChoiceMenuTests(unittest.TestCase):
    def test_active_selection_passes_through(self):
        with patch("penx.interactive_tool_run", return_value="Nmap: 80/tcp open http") as picker:
            self.assertEqual(
                penx._recon_choice_menu("example.test", False),
                ("Nmap: 80/tcp open http", False),
            )
        picker.assert_called_once_with("example.test")

    def test_passive_choice_switches_to_passive_recon(self):
        with patch("penx.interactive_tool_run", return_value=tools.ReconChoice.PASSIVE_ONLY), \
             patch("penx_app.scanners.passive_recon.passive_recon",
                   return_value="[RDAP]\n{\"name\": \"example.test\"}") as passive:
            self.assertEqual(
                penx._recon_choice_menu("example.test", False),
                ("[RDAP]\n{\"name\": \"example.test\"}", True),
            )
        passive.assert_called_once_with("example.test")

    def test_forced_passive_skips_tool_picker(self):
        with patch("penx.interactive_tool_run", side_effect=AssertionError("picker opened")), \
             patch("penx_app.scanners.passive_recon.passive_recon",
                   return_value="[RDAP]\n{\"name\": \"example.test\"}") as passive:
            self.assertEqual(
                penx._recon_choice_menu("example.test", True),
                ("[RDAP]\n{\"name\": \"example.test\"}", True),
            )
        passive.assert_called_once_with("example.test")

    def test_interruptions_and_tool_failures_propagate_to_caller(self):
        with patch("penx.interactive_tool_run", side_effect=KeyboardInterrupt("cancel")):
            with self.assertRaises(KeyboardInterrupt):
                penx._recon_choice_menu("example.test", False)
        with patch("penx.interactive_tool_run", side_effect=RuntimeError("boom")):
            with self.assertRaises(RuntimeError):
                penx._recon_choice_menu("example.test", False)


class FullScanFlagPropagationTests(unittest.TestCase):
    def test_picker_passive_choice_flows_into_assessment_as_passive(self):
        """The passive flag chosen at the picker must reach the model call."""
        passive_result = '[RDAP]\n{"name": "example.test"}'
        with patch("penx.prompt", return_value="example.test"), \
             patch("penx.llm_auth_preflight", return_value=True), \
             patch("penx.get_all_history", return_value=[]), \
             patch("penx.interactive_tool_run", return_value=tools.ReconChoice.PASSIVE_ONLY), \
             patch("penx_app.scanners.passive_recon.passive_recon", return_value=passive_result), \
             patch("penx.analyse_target", side_effect=RuntimeError("offline test")) as analyse, \
             patch("penx.create_session", return_value=42), \
             patch("penx.preserve_failed_recon", return_value="test.txt"), \
             patch("penx.delete_full_session"):
            penx.new_scan()
        analyse.assert_called_once_with("example.test", passive_result, passive_only=True)


class RunReconOnlyTests(unittest.TestCase):
    def _patched_flow(self):
        """Recon-only flow with every session/model boundary forbidden."""
        from contextlib import ExitStack
        stack = ExitStack()
        stack.enter_context(patch("penx.prompt", return_value="example.test"))
        stack.enter_context(patch("penx.get_all_history",
                                  side_effect=AssertionError("recon-only queried DB")))
        for name in ("penx.create_session", "penx.analyse_target", "penx.save_assessment",
                     "penx.get_session", "penx.llm_auth_preflight"):
            stack.enter_context(patch(name, side_effect=AssertionError(f"{name} reached")))
        return stack

    def test_active_recon_shows_no_session_or_model_boundary(self):
        from contextlib import redirect_stdout
        from io import StringIO
        with self._patched_flow(), \
             patch("penx.interactive_tool_run", return_value="Nmap: 80/tcp open http") as picker, \
             redirect_stdout(StringIO()) as out:
            penx.run_recon_only()
        picker.assert_called_once_with("example.test")
        self.assertEqual(out.getvalue().count("Nmap: 80/tcp open http"), 1)
        self.assertIn("Recon complete. No session or assessment created.", out.getvalue())

    def test_passive_choice_displays_passive_output(self):
        from contextlib import redirect_stdout
        from io import StringIO
        passive_result = '[RDAP]\n{"name": "example.test"}'
        with self._patched_flow(), \
             patch("penx.interactive_tool_run", return_value=tools.ReconChoice.PASSIVE_ONLY), \
             patch("penx_app.scanners.passive_recon.passive_recon", return_value=passive_result) as passive, \
             redirect_stdout(StringIO()) as out:
            penx.run_recon_only()
        passive.assert_called_once_with("example.test")
        self.assertEqual(out.getvalue().count(passive_result), 1)
        self.assertIn("Recon complete. No session or assessment created.", out.getvalue())

    def test_back_at_picker_leaves_no_session(self):
        from contextlib import redirect_stdout
        from io import StringIO
        with self._patched_flow(), \
             patch("penx.interactive_tool_run", return_value=None), \
             redirect_stdout(StringIO()) as out:
            penx.run_recon_only()
        self.assertIn("no session", out.getvalue())

    def test_back_and_empty_target_stop_before_any_tool(self):
        with patch("penx.prompt", return_value="back"), \
             patch("penx.get_all_history", side_effect=AssertionError("history queried")), \
             patch("penx.interactive_tool_run", side_effect=AssertionError("picker opened")):
            penx.run_recon_only()
        with patch("penx.prompt", return_value=""), \
             patch("penx.get_all_history", side_effect=AssertionError("history queried")), \
             patch("penx.interactive_tool_run", side_effect=AssertionError("picker opened")) as picker, \
             patch("penx.warn") as warning:
            penx.run_recon_only()
        picker.assert_not_called()
        self.assertTrue(any("No target entered" in str(c) for c in warning.call_args_list))

    def test_recon_only_does_not_access_stored_history(self):
        from contextlib import redirect_stdout
        from io import StringIO
        with self._patched_flow(), \
             patch("penx.interactive_tool_run", return_value="80/tcp open") as picker, \
             redirect_stdout(StringIO()) as out:
            penx.run_recon_only()
        picker.assert_called_once_with("example.test")
        self.assertIn("80/tcp open", out.getvalue())

    def test_interruption_and_tool_failure_are_reported_not_raised(self):
        from contextlib import redirect_stdout
        from io import StringIO
        with self._patched_flow(), \
             patch("penx.interactive_tool_run", side_effect=EOFError("eof")), \
             redirect_stdout(StringIO()) as out:
            penx.run_recon_only()
        self.assertIn("Recon interrupted", out.getvalue())
        with self._patched_flow(), \
             patch("penx.interactive_tool_run", side_effect=RuntimeError("boom")), \
             redirect_stdout(StringIO()) as out:
            penx.run_recon_only()
        self.assertIn("Recon failed", out.getvalue())
        self.assertIn("boom", out.getvalue())


class ReconMenuWiringTests(unittest.TestCase):
    def test_main_menu_recon_choice_routes_to_recon_only_not_scan(self):
        from contextlib import redirect_stdout
        from io import StringIO
        with patch("penx.banner") as banner, \
             patch("penx.run_recon_only") as recon, \
             patch("penx._execute_scan", side_effect=AssertionError("full scan ran")), \
             patch("builtins.input", side_effect=["14", "", "8"]), \
             redirect_stdout(StringIO()) as out:
            with self.assertRaises(SystemExit) as exit_status:
                penx.main_menu()
        self.assertEqual(exit_status.exception.code, 0)
        recon.assert_called_once_with()
        # The pause after the step consumes the blank input; without it the
        # loop would render a third menu before Exit.
        self.assertEqual(banner.call_count, 2)
        self.assertIn("Run Recon Tools (no assessment)", out.getvalue())

    def test_main_menu_choice_one_still_runs_full_scan(self):
        from penx_app.application.scan_outcome import ScanOutcome
        with patch("penx.banner") as banner, \
             patch("penx._execute_scan", return_value=ScanOutcome(False, False, "cancelled")) as scan, \
             patch("penx.run_recon_only", side_effect=AssertionError("recon-only ran")), \
             patch("builtins.input", side_effect=["1", "8"]):
            with self.assertRaises(SystemExit) as exit_status:
                penx.main_menu()
        self.assertEqual(exit_status.exception.code, 0)
        scan.assert_called_once_with()
        self.assertEqual(banner.call_count, 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
