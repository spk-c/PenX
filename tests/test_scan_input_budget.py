"""Offline tests for bounded model-facing scan evidence."""
import unittest
from penx_app.analysis.scan_input_budget import bound_scan_text


class ScanInputBudgetTests(unittest.TestCase):
    def test_short_scan_unchanged(self):
        raw = "[ NMAP OUTPUT ]\n80/tcp open http"
        self.assertEqual(bound_scan_text(raw), raw)

    def test_large_scan_keeps_important_lines_and_marks_omissions(self):
        raw = ("[ NMAP OUTPUT ]\n" + "filler data not relevant\n" * 5000 +
               "443/tcp open https Apache 2.4.61\n" +
               "[ NIKTO OUTPUT ]\n" + "filler data not relevant\n" * 5000 +
               "ERROR: Required module not found\n")
        compact = bound_scan_text(raw, 5000)
        self.assertLessEqual(len(compact), 5000)
        self.assertIn("TRUNCATED SCAN EVIDENCE", compact)
        self.assertIn("443/tcp open", compact)
        self.assertIn("Required module not found", compact)
        self.assertIn("[ NIKTO OUTPUT ]", compact)
        self.assertEqual(raw.count("filler data not relevant"), 10000)

    def test_minimum_budget_and_no_false_safety_claim(self):
        raw = "header\n" + "empty details\n" * 3000
        short = bound_scan_text(raw, 200)
        self.assertLessEqual(len(short), 2048)
        self.assertIn("does NOT establish its absence", short)


if __name__ == "__main__":
    unittest.main()
