"""Invalid legacy scanner adapter values must never become scan evidence."""
from __future__ import annotations

import unittest

from penx_app.application.scanner_execution import run_selected_structured
from penx_app.domain.scan_models import ScanRequest


class LegacyAdapterOutputContracts(unittest.TestCase):
    def run_fixture(self, outcome):
        result = run_selected_structured(
            ScanRequest("fixture.invalid", ("1",)),
            menu={"1": ("Nmap", lambda _target: outcome)},
        )
        self.assertEqual(len(result.results), 1)
        return result.results[0]

    def test_invalid_nontext_values_fail_closed(self):
        for invalid in (None, False, True, 0, [], {}, ["text"], b"output"):
            with self.subTest(invalid=invalid):
                row = self.run_fixture(invalid)
                self.assertEqual(row.status, "FAILED")
                self.assertFalse(row.evidence)
                self.assertIn("Unsupported scanner result type", row.text)

    def test_empty_legacy_string_is_not_complete(self):
        for invalid in ("", "  \t\n"):
            with self.subTest(invalid=invalid):
                row = self.run_fixture(invalid)
                self.assertEqual(row.status, "FAILED")
                self.assertFalse(row.evidence)

    def test_legacy_text_contract_is_preserved(self):
        row = self.run_fixture("synthetic scanner result")
        self.assertEqual(row.status, "COMPLETE")
        self.assertTrue(row.evidence)
        self.assertIn("synthetic scanner result", row.text)

    def test_legacy_error_text_remains_untrusted(self):
        row = self.run_fixture("[!] scanner error")
        self.assertEqual(row.status, "FAILED")
        self.assertFalse(row.evidence)


if __name__ == "__main__":
    unittest.main()
