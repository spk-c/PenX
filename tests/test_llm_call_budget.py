"""Offline call-budget contracts for the local LLM analysis pipeline.

PenX must keep model traffic bounded per target: one analysis conversation
loop (plus at most one synthesis turn after a full tool budget), one
structured report request and exactly one batched self-review, regardless
of how many findings the model produced. These tests pin that budget so a
future per-finding review loop is caught immediately.
"""
from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

from penx_app.analysis.analysis_pipeline import AnalysisPorts, analyse_target
from penx_app.settings import load_settings


class LlmCallBudgetContracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="penx-call-budget-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.model = Mock(return_value=(
            "VULN: Fixture finding | SEVERITY: low | CONFIDENCE: possible\n"
            "DESC: synthetic evidence only\n"
            "EVIDENCE: synthetic evidence marker\n"
            "RISK_LEVEL: LOW\nSUMMARY: Fixture observation only."
        ))
        self.structured = Mock(side_effect=ValueError("synthetic invalid JSON"))
        self.self_review = Mock(return_value={
            "flags": [], "review": "synthetic self-review", "adjusted_risk": "",
        })

    def make_ports(self, extract: Mock, run_tools: Mock) -> AnalysisPorts:
        return AnalysisPorts(
            format_report=lambda result: "",
            discover=lambda raw, **kwargs: {"candidates": []},
            research_plugins=lambda raw, **kwargs: {
                "observations": [], "checks": [], "candidates": [],
            },
            build_system_prompt=lambda: "Review synthetic evidence conservatively.",
            load_correction_rules=lambda: "",
            ask_llm=self.model,
            extract_tool_calls=extract,
            run_tool_calls=run_tools,
            request_structured_report=self.structured,
            self_review=self.self_review,
            verify_findings=lambda findings, raw, **kwargs: findings,
            exploitdb_lookup=lambda ids, **kwargs: {
                "status": "offline", "checked_cves": [], "matches": [],
            },
            live_output=lambda: False,
            app_root=self.root,
            emit=lambda line: None,
        )

    def settings(self, structured: str = "auto", max_loops: str = "1"):
        return load_settings(root=self.root, env={
            "PENX_STRUCTURED_OUTPUT": structured,
            "PENX_CVE_DISCOVERY": "off",
            "PENX_VERIFY_SOURCES": "off",
            "PENX_MAX_LOOPS": max_loops,
            "PENX_LLM_URL": "http://localhost:1234",
        })

    def test_standard_scan_makes_exactly_three_model_calls(self):
        ports = self.make_ports(
            Mock(return_value=[]),
            Mock(side_effect=AssertionError("No tool dispatch expected")),
        )
        result = analyse_target("example.test", "synthetic evidence marker",
                                settings=self.settings(), ports=ports)
        self.assertEqual(result["risk_level"], "LOW")
        # One conversation turn, one structured request, one self-review —
        # the per-target budget, independent of finding count.
        self.assertEqual(self.model.call_count, 1)
        self.assertEqual(self.structured.call_count, 1)
        self.assertEqual(self.self_review.call_count, 1)

    def test_many_findings_stay_in_a_single_batched_self_review(self):
        # 150 findings must not create 150 review calls: the self-review
        # port receives every finding name inside one report text.
        vuln_lines = [
            f"VULN: Finding {index} | SEVERITY: low | CONFIDENCE: possible\n"
            f"EVIDENCE: synthetic evidence marker"
            for index in range(150)
        ]
        self.model.return_value = "\n".join(vuln_lines) + (
            "\nRISK_LEVEL: LOW\nSUMMARY: Fixture observation only."
        )
        ports = self.make_ports(
            Mock(return_value=[]),
            Mock(side_effect=AssertionError("No tool dispatch expected")),
        )
        result = analyse_target("example.test", "synthetic evidence marker",
                                settings=self.settings(), ports=ports)
        self.assertEqual(self.model.call_count, 1)
        self.assertEqual(self.self_review.call_count, 1)
        # Every parsed finding name reaches the reviewer in one batch.
        reviewed_text = self.self_review.call_args.args[1]
        for index in (0, 74, 149):
            self.assertIn(f"Finding {index}", reviewed_text)
        # No finding is lost or duplicated by the pipeline.
        self.assertEqual(
            len(result["vulnerabilities"]) + len(result["recommendations"])
            + len(result["rejected_findings"]), 150,
        )

    def test_tool_loop_is_bounded_by_max_loops_plus_one(self):
        # The model keeps requesting *distinct* tools (identical repeats are
        # deduplicated earlier); the pipeline must stop after MAX_LOOPS
        # turns plus at most one synthesis call.
        tool_turn = "[TOOL: fixture]\nRISK_LEVEL: LOW\nSUMMARY: continue"
        final_turn = "RISK_LEVEL: LOW\nSUMMARY: bounded fixture."
        self.model.side_effect = [tool_turn, tool_turn, tool_turn, final_turn]
        extract = Mock(side_effect=[
            [("TOOL", "http_headers example.test")],
            [("TOOL", "http_headers example.test:8080")],
            [("TOOL", "tls_check example.test")],
            [],
        ])
        ports = self.make_ports(extract, Mock(
            return_value="[TOOL RESULT] synthetic evidence marker"))
        result = analyse_target("example.test", "synthetic evidence marker",
                                settings=self.settings(max_loops="3"), ports=ports)
        self.assertEqual(result["risk_level"], "LOW")
        # 3 tool turns + 1 synthesis; never more.
        self.assertEqual(self.model.call_count, 4)
        self.assertEqual(self.structured.call_count, 1)
        self.assertEqual(self.self_review.call_count, 1)


if __name__ == "__main__":
    unittest.main()
