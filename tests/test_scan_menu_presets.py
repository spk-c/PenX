"""Offline tests for scan presets and explicit active-scanner confirmation."""
import ast
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src" / "penx_app" / "scanners" / "tools.py"


class MenuTests(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self.inputs = []
        menu = {
            str(i): (f"tool{i}", lambda target, i=i: self.calls.append(i) or f"result{i}")
            for i in range(1, 10)
        }
        self.namespace = {
            "TOOLS_MENU": menu,
            "ReconChoice": type("ReconChoice", (), {"PASSIVE_ONLY": "passive"}),
            "format_recon_for_llm": lambda result: result,
        }
        self.navigation = types.ModuleType("cli_navigation")
        self.navigation.navigation_input = Mock(side_effect=lambda _: self.inputs.pop(0))
        self.navigation.is_back = lambda value: value.lower() in {"esc", "back"}
        self.navigation.show_back = lambda: None

    def choose(self, *answers):
        self.inputs = list(answers)
        with patch.dict(sys.modules, {"cli_navigation": self.navigation, "penx_app.cli.cli_navigation": self.navigation}):
            from penx_app.cli.scanner_menu import interactive_tool_run
            return interactive_tool_run('localhost', menu=self.namespace['TOOLS_MENU'],
                                        formatter=self.namespace['format_recon_for_llm'])

    def test_standard_runs_only_first_five(self):
        result = self.choose("a")
        self.assertEqual(self.calls, [1, 2, 3, 4, 5])
        self.assertEqual(len(result), 5)

    def test_nikto_preset(self):
        self.choose("n")
        self.assertEqual(self.calls, [1, 2, 3, 4, 5, 6])

    def test_full_requires_confirm_and_runs_all(self):
        self.choose("x", "yes")
        self.assertEqual(self.calls, list(range(1, 10)))

    def test_full_declined_runs_nothing(self):
        self.assertIsNone(self.choose("x", "n"))
        self.assertEqual(self.calls, [])

    def test_explicit_nuclei_requires_confirmation(self):
        self.assertIsNone(self.choose("1 7", "no"))
        self.assertEqual(self.calls, [])

    def test_no_partial_scan_on_invalid_choice(self):
        self.assertIsNone(self.choose("1 999"))
        self.assertEqual(self.calls, [])

    def test_comma_separated_and_deduplicated(self):
        self.choose("1, 2, 1")
        self.assertEqual(self.calls, [1, 2])


if __name__ == "__main__":
    unittest.main()
