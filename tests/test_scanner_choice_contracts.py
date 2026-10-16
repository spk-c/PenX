"""Pure CLI scanner selection must never broaden scope or bypass consent."""
from __future__ import annotations

import unittest

from penx_app.application.scanner_selection import resolve_scanner_selection
from penx_app.domain.scan_models import ReconChoice


class ScannerSelectionPolicyTests(unittest.TestCase):
    def setUp(self):
        self.keys = tuple(str(i) for i in range(1, 13))

    def choose(self, selection):
        return resolve_scanner_selection(selection, self.keys)

    def test_standard_and_full_presets_are_ordered_and_bounded(self):
        self.assertEqual(self.choose("a"), self.keys[:5])
        self.assertEqual(self.choose("n"), self.keys[:6])
        self.assertEqual(self.choose("x"), self.keys)

    def test_explicit_choices_keep_order_but_deduplicate_adapters(self):
        self.assertEqual(self.choose("1, 3 1 12"), ("1", "3", "12"))
        self.assertEqual(self.choose("  12,2 "), ("12", "2"))

    def test_passive_only_is_a_typed_distinct_choice(self):
        self.assertIs(self.choose("0"), ReconChoice.PASSIVE_ONLY)
        for choice in ("0 1", "1,0", "0,x"):
            with self.subTest(choice=choice):
                self.assertIsNone(self.choose(choice))

    def test_reject_unknown_or_partial_presets_instead_of_running_them(self):
        for choice in ("", " ", "13", "a 1", "1 13", "N x", "n,2", "--help"):
            with self.subTest(choice=choice):
                self.assertIsNone(self.choose(choice))

    def test_full_preset_is_limited_to_supplied_authorized_menu_keys(self):
        self.assertEqual(
            resolve_scanner_selection("x", ("2", "7")), ("2", "7")
        )
        self.assertIsNone(
            resolve_scanner_selection("1 2", ("2", "7"))
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
