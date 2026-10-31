"""Pk08 failure contracts: one configuration snapshot governs every model transport.

Covers the deterministic offline behavior of ask_llm / self_review /
summarize_tool_output under timeouts, empty, malformed and network-failed
responses, and the pipeline's auto/strict/off structured-output contract.
"""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from typing import Callable
from unittest.mock import Mock, patch
from dataclasses import replace

import requests

from penx_app.analysis import llm
from penx_app.analysis.analysis_pipeline import AnalysisPorts, analyse_target
from penx_app.settings import Settings, load_settings

LIVE_OFF = {"PENX_LIVE_OUTPUT": "0"}
TIMEOUT_MESSAGE = "[!] LLM request timed out. Check whether the model is still loading."


def snapshot_settings(root: Path, **overrides) -> Settings:
    env = {
        "PENX_LLM_URL": "http://localhost:4242",
        "PENX_MODEL": "snap-model",
        "PENX_LLM_API_KEY": "snap-key",
        "PENX_MAX_TOKENS": "4321",
        "PENX_TIMEOUT": "77",
        "PENX_TOP_K": "9",
    }
    env.update(overrides)
    return load_settings(root=root, env=env)


class AskLlmFailureContractTests(unittest.TestCase):
    """ask_llm must use the injected snapshot and map every failure to [!]."""

    def test_ask_llm_honors_injected_settings_snapshot(self):
        transport = Mock(return_value=("snap-model", "RISK_LEVEL: LOW\nSUMMARY: ok"))
        with tempfile.TemporaryDirectory() as temp, \
             patch.dict(os.environ, LIVE_OFF), \
             patch("penx_app.analysis.llm.complete_chat", transport), \
             patch("penx_app.analysis.llm.LLM_URL", "http://legacy:1/v1/chat/completions"), \
             patch("penx_app.analysis.llm.LLM_MODELS_URL", "http://legacy:1/v1/models"), \
             patch("penx_app.analysis.llm.LLM_BASE_URL", "http://legacy:1"), \
             patch("penx_app.analysis.llm.MODEL_NAME", "legacy-model"), \
             patch("penx_app.analysis.llm.LLM_API_KEY", "legacy-key"), \
             patch("penx_app.analysis.llm.MAX_TOKENS", 111), \
             patch("penx_app.analysis.llm.LLM_TIMEOUT", 22), \
             patch("penx_app.analysis.llm.TOP_K", 3):
            settings = snapshot_settings(Path(temp))
            result = llm.ask_llm([{"role": "user", "content": "assess"}], settings=settings)
        self.assertEqual(result, "RISK_LEVEL: LOW\nSUMMARY: ok")
        kwargs = transport.call_args.kwargs
        self.assertEqual(kwargs["url"], "http://localhost:4242/v1/chat/completions")
        self.assertEqual(kwargs["models_url"], "http://localhost:4242/v1/models")
        self.assertEqual(kwargs["model_name"], "snap-model")
        self.assertEqual(kwargs["api_key"], "snap-key")
        self.assertEqual(kwargs["max_tokens"], 4321)
        self.assertEqual(kwargs["timeout"], 77)
        self.assertEqual(kwargs["top_k"], 9)

    def test_ask_llm_without_settings_uses_module_globals(self):
        transport = Mock(return_value=("legacy-model", "ok"))
        with tempfile.TemporaryDirectory() as temp, \
             patch.dict(os.environ, LIVE_OFF), \
             patch("penx_app.analysis.llm.complete_chat", transport), \
             patch("penx_app.analysis.llm.LLM_URL", "http://legacy:1/v1/chat/completions"), \
             patch("penx_app.analysis.llm.LLM_MODELS_URL", "http://legacy:1/v1/models"), \
             patch("penx_app.analysis.llm.MODEL_NAME", "legacy-model"), \
             patch("penx_app.analysis.llm.LLM_API_KEY", "legacy-key"), \
             patch("penx_app.analysis.llm.MAX_TOKENS", 111), \
             patch("penx_app.analysis.llm.LLM_TIMEOUT", 22), \
             patch("penx_app.analysis.llm.TOP_K", 3):
            llm.ask_llm([{"role": "user", "content": "assess"}])
        kwargs = transport.call_args.kwargs
        self.assertEqual(kwargs["url"], "http://legacy:1/v1/chat/completions")
        self.assertEqual(kwargs["model_name"], "legacy-model")
        self.assertEqual(kwargs["api_key"], "legacy-key")
        self.assertEqual(kwargs["max_tokens"], 111)
        self.assertEqual(kwargs["timeout"], 22)
        self.assertEqual(kwargs["top_k"], 3)

    def test_ask_llm_timeout_maps_to_actionable_message(self):
        with patch.dict(os.environ, LIVE_OFF), \
             patch("penx_app.analysis.llm.complete_chat", side_effect=requests.Timeout("slow")):
            result = llm.ask_llm([{"role": "user", "content": "x"}])
        self.assertTrue(result.startswith("[!]"))
        self.assertIn("timed out", result)

    def test_ask_llm_connection_error_reports_snapshot_base_url(self):
        with tempfile.TemporaryDirectory() as temp, \
             patch.dict(os.environ, LIVE_OFF), \
             patch("penx_app.analysis.llm.complete_chat", side_effect=requests.ConnectionError("offline")):
            settings = snapshot_settings(Path(temp))
            result = llm.ask_llm([{"role": "user", "content": "x"}], settings=settings)
        self.assertTrue(result.startswith("[!]"))
        self.assertIn("http://localhost:4242", result)

    def test_ask_llm_http_error_exposes_status(self):
        response = requests.Response()
        response.status_code = 500
        error = requests.HTTPError("500 Server Error", response=response)
        with patch.dict(os.environ, LIVE_OFF), \
             patch("penx_app.analysis.llm.complete_chat", side_effect=error):
            result = llm.ask_llm([{"role": "user", "content": "x"}])
        self.assertTrue(result.startswith("[!]"))
        self.assertIn("500", result)

    def test_ask_llm_unexpected_error_is_bounded(self):
        with patch.dict(os.environ, LIVE_OFF), \
             patch("penx_app.analysis.llm.complete_chat", side_effect=ValueError("boom")):
            result = llm.ask_llm([{"role": "user", "content": "x"}])
        self.assertTrue(result.startswith("[!]"))
        self.assertIn("Unexpected LLM error: boom", result)


class SelfReviewContractTests(unittest.TestCase):
    def test_self_review_uses_injected_ask(self):
        seen = {}

        def fake_ask(messages):
            seen["messages"] = messages
            return (
                "REVIEW: Open port 22 | VERDICT: valid\n"
                "EVIDENCE: 22/tcp open ssh\n"
                "REVIEW: Invented CVE | VERDICT: hallucination\n"
                "ISSUE: No scanner evidence for CVE-2024-9999\n"
                "ADJUSTED_RISK_LEVEL: LOW"
            )

        result = llm.self_review(
            "22/tcp open ssh", "VULN: Open port 22\nVULN: Invented CVE", "", ask=fake_ask
        )
        self.assertEqual(result["adjusted_risk"], "LOW")
        self.assertEqual(len(result["flags"]), 2)
        self.assertEqual(result["flags"][0]["verdict"], "valid")
        self.assertEqual(result["flags"][1]["verdict"], "hallucination")
        content = "\n".join(str(m.get("content", "")) for m in seen["messages"])
        self.assertIn("RAW SCAN DATA", content)
        self.assertIn("22/tcp open ssh", content)

    def test_self_review_transport_failure_yields_empty_contract(self):
        result = llm.self_review("evidence", "analysis", "", ask=lambda m: TIMEOUT_MESSAGE)
        self.assertEqual(result, {"review": "", "adjusted_risk": "", "flags": []})


class SummarizeContractTests(unittest.TestCase):
    def test_summarize_short_output_skips_transport(self):
        complete = Mock()
        self.assertEqual(llm.summarize_tool_output("short", complete=complete), "short")
        complete.assert_not_called()

    def test_summarize_uses_injected_transport(self):
        complete = Mock(return_value=("local-model", "- bullet"))
        raw = "x" * 500
        self.assertEqual(llm.summarize_tool_output(raw, complete=complete), "- bullet")
        complete.assert_called_once()
        messages = complete.call_args.args[0]
        self.assertIn("Compress this tool output", messages[-1]["content"])

    def test_summarize_failure_preserves_raw_evidence(self):
        raw = "x" * 500
        self.assertEqual(
            llm.summarize_tool_output(raw, complete=Mock(side_effect=RuntimeError("offline"))),
            raw,
        )

    def test_summarize_empty_summary_preserves_raw_evidence(self):
        raw = "x" * 500
        self.assertEqual(
            llm.summarize_tool_output(raw, complete=Mock(return_value=("m", ""))), raw
        )


class PipelineFailureContractTests(unittest.TestCase):
    """The pipeline must fail loudly on transport failures and malformed finals."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="penx-failure-fixture-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.model = Mock(return_value="RISK_LEVEL: LOW\nSUMMARY: Fixture observation only.")
        self.structured = Mock(side_effect=ValueError("synthetic invalid JSON"))
        self.dispatch = Mock(side_effect=AssertionError("No model tool dispatch allowed"))
        self.extract = Mock(return_value=[])
        self.notes: list = []
        self.ports = AnalysisPorts(
            format_report=lambda result: "",
            discover=lambda raw, **kwargs: {"candidates": []},
            research_plugins=lambda raw, **kwargs: {
                "observations": [], "checks": [], "candidates": [],
            },
            build_system_prompt=lambda: "Review synthetic evidence conservatively.",
            load_correction_rules=lambda: "",
            ask_llm=self.model,
            extract_tool_calls=self.extract,
            run_tool_calls=self.dispatch,
            request_structured_report=self.structured,
            self_review=lambda raw, items, rules: {
                "flags": [], "review": "", "adjusted_risk": "",
            },
            verify_findings=lambda findings, raw, **kwargs: findings,
            exploitdb_lookup=lambda ids, **kwargs: {
                "status": "offline", "checked_cves": [], "matches": [],
            },
            live_output=lambda: False,
            app_root=self.root,
            emit=self.notes.append,
        )

    def settings(self, mode: str = "off", loops: str = "1"):
        return load_settings(root=self.root, env={
            "PENX_STRUCTURED_OUTPUT": mode,
            "PENX_CVE_DISCOVERY": "off",
            "PENX_VERIFY_SOURCES": "off",
            "PENX_MAX_LOOPS": loops,
            "PENX_LLM_URL": "http://localhost:1234",
        })

    def test_source_result_formatters_are_injected(self):
        plugin = Mock(return_value="offline WordPress source observations")
        exploit = Mock(return_value="offline ExploitDB references")
        ports = replace(self.ports, format_plugin_report=plugin,
                        format_exploitdb_report=exploit)
        result = analyse_target("example.test", "synthetic evidence",
                                settings=self.settings(), ports=ports)
        self.assertEqual(result["risk_level"], "LOW")
        plugin.assert_called_once()
        exploit.assert_called_once()

    def test_empty_model_response_fails_analysis(self):
        self.model.return_value = ""
        with self.assertRaisesRegex(RuntimeError, "Local LLM analysis failed"):
            analyse_target("example.test", "synthetic evidence",
                          settings=self.settings(), ports=self.ports)

    def test_timeout_message_fails_analysis(self):
        self.model.return_value = TIMEOUT_MESSAGE
        with self.assertRaisesRegex(RuntimeError, "Local LLM analysis failed"):
            analyse_target("example.test", "synthetic evidence",
                          settings=self.settings(), ports=self.ports)

    def test_network_failure_message_fails_analysis(self):
        self.model.return_value = "[!] Cannot connect to the local LLM at http://localhost:1234."
        with self.assertRaisesRegex(RuntimeError, "Local LLM analysis failed"):
            analyse_target("example.test", "synthetic evidence",
                          settings=self.settings(), ports=self.ports)

    def test_final_synthesis_failure_after_tool_dispatch(self):
        self.model.side_effect = [
            "[TOOL: nmap example.test]\nRISK_LEVEL: LOW",
            TIMEOUT_MESSAGE,
        ]
        self.extract.return_value = [("TOOL", "nmap example.test")]
        self.dispatch.side_effect = None
        self.dispatch.return_value = "fixture output"
        with self.assertRaisesRegex(RuntimeError, "Final synthesis after tool dispatch failed"):
            analyse_target("example.test", "synthetic evidence",
                          settings=self.settings(), ports=self.ports)

    def test_final_synthesis_requesting_more_tools_is_rejected(self):
        self.model.side_effect = [
            "[TOOL: nmap example.test]\nRISK_LEVEL: LOW",
            "[TOOL: nmap -sV example.test]\nRISK_LEVEL: LOW\nSUMMARY: more tools",
        ]
        self.extract.return_value = [("TOOL", "nmap example.test")]
        self.dispatch.side_effect = None
        self.dispatch.return_value = "fixture output"
        with self.assertRaisesRegex(RuntimeError, "Model requested more tools after its tool budget"):
            analyse_target("example.test", "synthetic evidence",
                          settings=self.settings(), ports=self.ports)

    def test_malformed_final_text_yields_unknown_risk_and_empty_summary(self):
        self.model.return_value = (
            "The model produced prose without the required RISK_LEVEL or SUMMARY labels."
        )
        result = analyse_target("example.test", "synthetic evidence",
                                settings=self.settings(), ports=self.ports)
        self.assertEqual(result["risk_level"], "UNKNOWN")
        self.assertEqual(result["summary"], "")

    def test_auto_mode_uses_valid_structured_report(self):
        payload = {
            "vulnerabilities": [{
                "vuln_name": "Outdated SSH server version", "severity": "low",
                "confidence": "likely", "port": "22", "service": "ssh",
                "description": "SSH banner predates current release",
                "evidence": "22/tcp open ssh",
                "fix": "Restrict access", "cve_ids": [],
            }],
            "recommendations": [{"vuln_name": "rec-one", "description": "Harden"}],
            "exploits": [],
            "risk_level": "LOW",
            "summary": "Structured summary",
        }
        self.structured.side_effect = None
        self.structured.return_value = payload
        self.model.return_value = "RISK_LEVEL: MEDIUM\nSUMMARY: Text disagrees."
        result = analyse_target("example.test", "synthetic scan\n22/tcp open ssh",
                                settings=self.settings(mode="auto"), ports=self.ports)
        self.assertEqual(result["risk_level"], "LOW")
        self.assertEqual(result["summary"], "Structured summary")
        self.assertEqual(len(result["vulnerabilities"]), 1)
        self.assertEqual(result["vulnerabilities"][0]["vuln_name"], "Outdated SSH server version")
        self.structured.assert_called_once()

    def test_auto_mode_falls_back_to_text_when_structured_report_fails(self):
        self.structured.side_effect = ValueError("synthetic invalid JSON")
        self.model.return_value = "RISK_LEVEL: LOW\nSUMMARY: Text only."
        result = analyse_target("example.test", "synthetic evidence",
                                settings=self.settings(mode="auto"), ports=self.ports)
        self.assertEqual(result["risk_level"], "LOW")
        self.assertEqual(result["summary"], "Text only.")

    def test_strict_mode_uses_valid_structured_report(self):
        self.structured.side_effect = None
        self.structured.return_value = {
            "vulnerabilities": [],
            "recommendations": [],
            "exploits": [],
            "risk_level": "MEDIUM",
            "summary": "Strict structured summary",
        }
        self.model.return_value = "RISK_LEVEL: LOW\nSUMMARY: Text disagrees."
        result = analyse_target("example.test", "synthetic evidence",
                                settings=self.settings(mode="strict"), ports=self.ports)
        self.assertEqual(result["risk_level"], "MEDIUM")
        self.assertEqual(result["summary"], "Strict structured summary")

    def test_strict_mode_invalid_structured_report_fails_analysis(self):
        self.structured.side_effect = ValueError("synthetic invalid JSON")
        self.model.return_value = "RISK_LEVEL: LOW\nSUMMARY: Text only."
        with self.assertRaisesRegex(RuntimeError, "Structured LLM output failed"):
            analyse_target("example.test", "synthetic evidence",
                          settings=self.settings(mode="strict"), ports=self.ports)


class SourceDispatchInjectionTests(unittest.TestCase):
    def test_dispatch_clients_are_injected_without_expanding_tool_scope(self):
        from penx_app.analysis import llm as model
        scanner = Mock()
        search = Mock()
        summarizer = Mock()
        collector = []
        calls = [("SEARCH", "CVE-2024-0001")]
        with patch.object(model, "dispatch_directives", return_value="fixture") as dispatch:
            result = model.run_tool_calls(
                calls, authorized_target="example.test", raw_collector=collector,
                scanner_runner=scanner, search_runner=search,
                summarizer=summarizer,
            )
        self.assertEqual(result, "fixture")
        dispatch.assert_called_once_with(
            calls, authorized_target="example.test", raw_collector=collector,
            scanner_runner=scanner, search_runner=search, summarizer=summarizer,
        )


class FacadeSnapshotWiringTests(unittest.TestCase):
    """penx_app.analysis.llm.analyse_target must bind one snapshot to ask/review/summarize ports."""

    def test_pipeline_ports_receive_settings_bound_transports(self):
        ask_mock = Mock(side_effect=[
            "[TOOL: nmap example.test]\nRISK_LEVEL: LOW\nSUMMARY: pending",
            "RISK_LEVEL: LOW\nSUMMARY: Snapshot bound.",
        ])
        review_mock = Mock(return_value={"flags": [], "review": "", "adjusted_risk": ""})
        summarize_mock = Mock(side_effect=lambda text, complete=None: text)
        with tempfile.TemporaryDirectory() as temp, \
             patch("penx_app.analysis.llm.LLM_TIMEOUT", 77), \
             patch("penx_app.analysis.llm.MAX_TOKENS", 4321), \
             patch("penx_app.analysis.llm.MODEL_NAME", "snap-model"), \
             patch("penx_app.analysis.llm.LLM_API_KEY", "snap-key"), \
             patch("penx_app.analysis.llm.STRUCTURED_MODE", "off"), \
             patch("penx_app.analysis.llm.VERIFY_SOURCES", False), \
             patch("penx_app.analysis.llm.discover", return_value={"candidates": []}), \
             patch("penx_app.analysis.llm.format_report", return_value=""), \
             patch("penx_app.analysis.llm.research_plugins", return_value={
                 "observations": [], "checks": [], "candidates": [],
             }), \
             patch("penx_app.analysis.llm.build_system_prompt", return_value="System prompt"), \
             patch("penx_app.analysis.llm.load_correction_rules", return_value=""), \
             patch("penx_app.analysis.llm.ask_llm", ask_mock), \
             patch("penx_app.analysis.llm.self_review", review_mock), \
             patch("penx_app.analysis.llm.summarize_tool_output", summarize_mock), \
             patch("penx_app.analysis.llm.run_tool_by_command", return_value="x" * 600), \
             patch("penx_app.analysis.llm.verify_findings", side_effect=lambda x, *_a, **_k: x), \
             patch("penx_app.analysis.llm.exploitdb_lookup", return_value={
                 "status": "offline", "checked_cves": [], "matches": [],
             }):
            result = llm.analyse_target("example.test", "offline evidence")
        self.assertEqual(result["risk_level"], "LOW")
        # The pipeline transport received the snapshot, not the module globals.
        first = ask_mock.call_args_list[0]
        snapshot = first.kwargs["settings"]
        self.assertIsInstance(snapshot, Settings)
        self.assertEqual(snapshot.LLM_TIMEOUT, 77)
        self.assertEqual(snapshot.MAX_TOKENS, 4321)
        self.assertEqual(snapshot.MODEL_NAME, "snap-model")
        self.assertEqual(snapshot.LLM_API_KEY, "snap-key")
        # Self-review and tool-output compression are bound to the same snapshot.
        self.assertIn("ask", review_mock.call_args.kwargs)
        self.assertIsInstance(review_mock.call_args.kwargs["ask"], Callable)
        self.assertIn("complete", summarize_mock.call_args.kwargs)


if __name__ == "__main__":
    unittest.main(verbosity=2)
