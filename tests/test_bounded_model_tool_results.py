"""Protect model context from unbounded tool output and optional summarizers.

Only fake adapters; no scanning, subprocesses, HTTP or external LLM calls.
"""
from __future__ import annotations

import unittest
from unittest.mock import Mock

from penx_app.analysis.ai_tool_protocol import (
    MAX_TOOL_INPUT_CHARS, MAX_TOOL_RESULT_CHARS,
    MAX_TOOL_ROUND_CHARS, dispatch_directives,
)
from penx_app.domain.scan_models import ScannerOutput


class BoundedModelToolResultsTests(unittest.TestCase):
    def dispatch(self, calls, *, scanner=None, summarizer=None,
                 search=None, collector=None):
        return dispatch_directives(
            calls, authorized_target="example.test",
            scanner_runner=scanner or Mock(return_value="safe"),
            search_runner=search or Mock(return_value="safe"),
            summarizer=summarizer or (lambda value: value),
            raw_collector=collector,
        )

    def test_large_raw_fallback_never_enters_model_context_unbounded(self):
        original = ScannerOutput("443/tcp open HTTPS " + "e" * 300_000,
                                 status="COMPLETE", evidence=True)
        archive = []
        summary = Mock(side_effect=lambda text: text)
        result = self.dispatch(
            [("TOOL", "nmap example.test")],
            scanner=Mock(return_value=original), summarizer=summary,
            collector=archive,
        )
        self.assertLessEqual(len(result), MAX_TOOL_RESULT_CHARS + 250)
        self.assertIn("Tool result truncated", result)
        self.assertEqual(len(archive), 1)
        self.assertGreater(len(archive[0]), 100_000)
        self.assertLessEqual(len(summary.call_args.args[0]), MAX_TOOL_INPUT_CHARS)

    def test_malfunctioning_summarizer_output_is_bounded_too(self):
        model_summary = "S" * 1_000_000
        result = self.dispatch(
            [("SEARCH", "CVE-2024-6387")],
            summarizer=Mock(return_value=model_summary),
        )
        self.assertLessEqual(len(result), MAX_TOOL_RESULT_CHARS + 250)
        self.assertIn("Tool result truncated", result)

    def test_multiple_large_results_have_hard_combined_limit(self):
        calls = [("SEARCH", "CVE-2024-%04d" % x) for x in range(12)]
        search = Mock(return_value="A" * 200_000)
        result = self.dispatch(calls, search=search)
        self.assertLessEqual(len(result), MAX_TOOL_ROUND_CHARS)
        self.assertLessEqual(search.call_count, 12)
        self.assertGreaterEqual(search.call_count, 1)

    def test_direct_dispatch_does_not_execute_oversized_commands(self):
        scanner, search = Mock(), Mock()
        result = self.dispatch(
            [("TOOL", "nmap " + "X" * 10_000),
             ("SEARCH", "CVE-" + "Y" * 10_000)],
            scanner=scanner, search=search,
        )
        scanner.assert_not_called()
        search.assert_not_called()
        self.assertNotIn("X" * 500, result)
        self.assertNotIn("Y" * 500, result)
        self.assertIn("Unknown call type", result)

    def test_nonstring_summary_becomes_diagnostic(self):
        value = self.dispatch(
            [("SEARCH", "CVE-2024-6387")],
            summarizer=lambda _s: {"invalid": "shape"},
        )
        self.assertIn("Tool summarizer returned unsupported", value)

    def test_regular_tool_output_still_enters_evidence_and_model_context(self):
        archive = []
        result = self.dispatch(
            [("TOOL", "nmap example.test")],
            scanner=Mock(return_value=ScannerOutput(
                "443/tcp open HTTPS", status="COMPLETE", evidence=True,
            )),
            collector=archive,
        )
        self.assertIn("[TOOL RESULT: nmap example.test]", result)
        self.assertIn("443/tcp open HTTPS", result)
        self.assertEqual(len(archive), 1)
        self.assertIn("443/tcp open HTTPS", archive[0])


if __name__ == "__main__":
    unittest.main()
