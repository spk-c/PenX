"""Regression tests for duplicate finding pairing in session diffs."""
import unittest
from unittest.mock import patch

from penx_app.application.scan_trends import compare_sessions


def session(number):
    return {"history": (number, "example.com", "2026-10-16"), "summary": None}


def finding(severity):
    return {"name": "Example", "severity": severity, "confidence": "possible",
            "port": "443", "service": "https"}


class DuplicateSeverityPairingTests(unittest.TestCase):
    def compare(self, before, after):
        with patch("penx_app.application.scan_trends._findings",
                   side_effect=[{("example", "443", "https"): [finding(x) for x in before]},
                                {("example", "443", "https"): [finding(x) for x in after]}]):
            return compare_sessions(session(1), session(2))

    def test_removed_high_preserves_low(self):
        diff = self.compare(["high", "low"], ["low"])
        self.assertEqual([x["severity"] for x in diff["persistent_findings"]], ["low"])
        self.assertEqual([x["severity"] for x in diff["not_observed_findings"]], ["high"])
        self.assertEqual(diff["severity_changes"], [])

    def test_insertion_order_does_not_create_change(self):
        diff = self.compare(["high", "low"], ["low", "high"])
        self.assertEqual(len(diff["persistent_findings"]), 2)
        self.assertEqual(diff["severity_changes"], [])

    def test_real_severity_change(self):
        diff = self.compare(["high"], ["medium"])
        self.assertEqual([(x["from"], x["to"]) for x in diff["severity_changes"]],
                         [("high", "medium")])

    def test_new_duplicate_preserves_existing(self):
        diff = self.compare(["low"], ["high", "low"])
        self.assertEqual(len(diff["persistent_findings"]), 1)
        self.assertEqual([x["severity"] for x in diff["new_findings"]], ["high"])


if __name__ == "__main__":
    unittest.main()
