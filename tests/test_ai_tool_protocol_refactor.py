"""LLM directive protocol refactor: safe parsing and injection of adapters."""
from __future__ import annotations
import unittest
from unittest.mock import Mock, patch

from penx_app.analysis import ai_tool_protocol
from penx_app.domain.scan_models import ScannerOutput
import llm


class ToolProtocolRefactorTests(unittest.TestCase):
    def test_directives_preserve_ipv6_and_order_without_adjacent_tags(self):
        raw = "[SEARCH: CVE-2024-6387] [TOOL: nmap [::1]]\n[TOOL: nmap example.test]"
        expected = [("SEARCH", "CVE-2024-6387"),
                    ("TOOL", "nmap [::1]"), ("TOOL", "nmap example.test")]
        self.assertEqual(ai_tool_protocol.parse_directives(raw), expected)
        self.assertEqual(llm.extract_tool_calls(raw), expected)

    def test_dispatch_injects_fixed_scoped_adapters_and_archives_tool_output(self):
        scans = Mock(return_value="443/tcp open HTTPS")
        searches = Mock(return_value="CVE references")
        summarized = Mock(side_effect=lambda value: value)
        collected = []
        calls = [("SEARCH", "CVE-2024-6387"), ("TOOL", "nmap example.test")]
        result = ai_tool_protocol.dispatch_directives(
            calls, authorized_target="example.test", raw_collector=collected,
            scanner_runner=scans, search_runner=searches, summarizer=summarized)
        scans.assert_called_once_with("nmap example.test", authorized_target="example.test")
        searches.assert_called_once_with("CVE-2024-6387")
        self.assertEqual(len(collected), 1)
        self.assertIn("443/tcp", collected[0])
        self.assertIn("[TOOL RESULT: nmap example.test]", result)

    def test_blocked_or_empty_output_cannot_be_archived_as_evidence(self):
        outcomes = iter(["[!] Blocked model tool call", None])
        collected = []
        result = ai_tool_protocol.dispatch_directives(
            [("TOOL", "nmap wrong"), ("TOOL", "nmap example.test")],
            authorized_target="example.test", raw_collector=collected,
            scanner_runner=lambda *_a, **_k: next(outcomes),
            search_runner=lambda *_a: "",
            summarizer=lambda s: s,
        )
        self.assertEqual(collected, [])
        self.assertIn("Tool returned no output", result)

    def test_failed_or_partial_typed_scanner_output_is_never_archived(self):
        for status, evidence, body in (
            ("FAILED", False, "[EXIT CODE 2]\\nsynthetic data"),
            ("PARTIAL", True, "partial output before timeout"),
            ("PARTIAL", False, "partial output"),
            ("COMPLETE", False, "diagnostic without verified evidence"),
        ):
            with self.subTest(status=status, evidence=evidence):
                value = ScannerOutput(body, status=status, evidence=evidence)
                collected = []
                result = ai_tool_protocol.dispatch_directives(
                    [("TOOL", "nmap fixture.invalid")], raw_collector=collected,
                    scanner_runner=lambda *_args, **_kwargs: value,
                    search_runner=lambda _query: "",
                    summarizer=lambda value: value,
                )
                self.assertEqual(collected, [])
                self.assertIn("TOOL RESULT", result)

    def test_valid_typed_scanner_output_remains_archivable(self):
        output = ScannerOutput("443/tcp open HTTPS", status="COMPLETE", evidence=True)
        collected = []
        ai_tool_protocol.dispatch_directives(
            [("TOOL", "nmap fixture.invalid")], raw_collector=collected,
            scanner_runner=lambda *_args, **_kwargs: output,
            search_runner=lambda _query: "", summarizer=lambda value: value,
        )
        self.assertEqual(len(collected), 1)
        self.assertIn("443/tcp", collected[0])

    def test_legacy_diagnostics_and_nontext_results_are_not_archived(self):
        for value in ("[EXIT CODE 1] failed", "[ERROR] broken",
                      "Traceback synthetic", "", "  ", False, ["fake"], {}):
            with self.subTest(value=value):
                collected = []
                ai_tool_protocol.dispatch_directives(
                    [("TOOL", "nmap fixture.invalid")], raw_collector=collected,
                    scanner_runner=lambda *_args, **_kwargs: value,
                    search_runner=lambda _query: "",
                    summarizer=lambda text: text,
                )
                self.assertEqual(collected, [])

    def test_model_generated_directives_are_bounded_per_round(self):
        limit = ai_tool_protocol.MAX_DIRECTIVES_PER_ROUND
        response = " ".join("[SEARCH: fixture-%d]" % i for i in range(limit + 40))
        calls = ai_tool_protocol.parse_directives(response)
        self.assertEqual(len(calls), limit)
        self.assertEqual(calls[0], ("SEARCH", "fixture-0"))
        self.assertEqual(calls[-1], ("SEARCH", "fixture-%d" % (limit - 1)))

    def test_direct_dispatch_is_bounded_even_without_parser(self):
        limit = ai_tool_protocol.MAX_DIRECTIVES_PER_ROUND
        calls = [("SEARCH", "fixture-%d" % i) for i in range(limit + 40)]
        search = Mock(return_value="fixture")
        result = ai_tool_protocol.dispatch_directives(
            calls, scanner_runner=Mock(),
            search_runner=search, summarizer=lambda text: text)
        self.assertEqual(search.call_count, limit)
        self.assertIn("Skipped 40 model tool/search requests", result)
        self.assertNotIn("SEARCH RESULT: fixture-%d" % limit, result)

    def test_public_llm_patch_points_still_work(self):
        with patch("llm.run_tool_by_command", return_value="fixture") as scanner, \
             patch("llm.summarize_tool_output", side_effect=lambda x: x):
            result = llm.run_tool_calls([("TOOL", "nmap example.test")],
                                        authorized_target="example.test")
        scanner.assert_called_once_with("nmap example.test", authorized_target="example.test")
        self.assertIn("fixture", result)

    def test_unrecognized_command_type_never_invokes_an_adapter(self):
        scanner, search = Mock(), Mock()
        result = ai_tool_protocol.dispatch_directives(
            [("EXEC", "rm -rf /")], authorized_target="example.test",
            scanner_runner=scanner, search_runner=search, summarizer=lambda x: x)
        self.assertIn("Unknown call type", result)
        scanner.assert_not_called()
        search.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
