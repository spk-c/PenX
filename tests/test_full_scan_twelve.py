"""Offline tests for Full Scan selection including new discovery tools."""
import ast
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

SOURCE = Path(__file__).resolve().parents[1] / "src" / "penx_app" / "scanners" / "tools.py"


class FullScanMenuTests(unittest.TestCase):
    def setUp(self):
        self.called = []
        self.menu = {key: (key, lambda target, k=key: self.called.append(k) or k)
                     for key in ("1", "2", "3", "4", "5", "6", "7", "8", "9", "s", "c", "d")}
        self.namespace = {"TOOLS_MENU": self.menu,
                          "ReconChoice": type("ReconChoice", (), {"PASSIVE_ONLY": "passive"}),
                          "format_recon_for_llm": lambda result: result,
                          # Isolate menu selection; HTTP-508 handling has its own
                          # integration regressions in test_native_web_scanners.
                          "_RESOURCE_SENSITIVE_KEYS": {"6", "7", "8", "9", "c"},
                          "_resource_limit_observed": lambda results: False}
        self.navigation = types.ModuleType("cli_navigation")
        self.navigation.is_back = lambda value: value in ("esc", "back", "b")
        self.navigation.show_back = lambda: None

    def choose(self, *answers):
        queue = iter(answers)
        self.navigation.navigation_input = Mock(side_effect=lambda _: next(queue))
        with patch.dict(sys.modules, {"cli_navigation": self.navigation, "penx_app.cli.cli_navigation": self.navigation}):
            from penx_app.cli.scanner_menu import interactive_tool_run
            return interactive_tool_run('example.test', menu=self.namespace['TOOLS_MENU'],
                                        formatter=self.namespace['format_recon_for_llm'])

    def test_full_includes_all_twelve(self):
        result = self.choose("x", "yes")
        self.assertEqual(self.called, list(self.menu))
        self.assertEqual(len(result), 12)

    def test_full_decline_starts_nothing(self):
        self.assertIsNone(self.choose("x", "no"))
        self.assertEqual(self.called, [])

    def test_katana_manual_choice_requires_consent(self):
        self.assertIsNone(self.choose("b c d", "n"))
        self.assertEqual(self.called, [])

    def test_standard_presets_unchanged(self):
        self.choose("a")
        self.assertEqual(self.called, list(self.menu)[:5])
        self.called.clear()
        self.choose("n")
        self.assertEqual(self.called, list(self.menu)[:6])

    def test_manual_new_tools(self):
        result = self.choose("s d")
        self.assertEqual(self.called, ["s", "d"])
        self.assertEqual(len(result), 2)

    def test_back_alias_is_not_a_scanner(self):
        self.assertIsNone(self.choose("b"))
        self.assertEqual(self.called, [])

    def test_subfinder_selectable_with_real_back_alias(self):
        self.choose("s")
        self.assertEqual(self.called, ["s"])

    def test_invalid_choice_starts_nothing(self):
        self.assertIsNone(self.choose("1 unknown"))
        self.assertEqual(self.called, [])


if __name__ == "__main__":
    unittest.main()
