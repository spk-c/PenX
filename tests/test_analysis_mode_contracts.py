"""Offline end-to-end analysis-mode contracts with injected model/source ports."""
from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

from penx_app.analysis.analysis_pipeline import AnalysisPorts, analyse_target
from penx_app.settings import load_settings


class AnalysisModeContracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="penx-mode-fixture-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.structured = Mock(side_effect=ValueError("synthetic invalid JSON"))
        self.model = Mock(return_value="RISK_LEVEL: LOW\nSUMMARY: Fixture observation only.")
        self.dispatch = Mock(side_effect=AssertionError("No model tool dispatch allowed"))
        self.extract = Mock(return_value=[])
        self.notes = []
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

    def settings(self, mode: str):
        return load_settings(root=self.root, env={
            "PENX_STRUCTURED_OUTPUT": mode,
            "PENX_CVE_DISCOVERY": "off",
            "PENX_VERIFY_SOURCES": "off",
            "PENX_MAX_LOOPS": "1",
            "PENX_LLM_URL": "http://localhost:1234",
        })

    def test_auto_mode_falls_back_to_legacy_text_when_json_is_invalid(self):
        result = analyse_target(
            "example.test", "synthetic scan evidence", settings=self.settings("auto"),
            ports=self.ports,
        )
        self.assertEqual(result["risk_level"], "LOW")
        self.assertEqual(result["exploits"], [])
        self.structured.assert_called_once()
        self.dispatch.assert_not_called()
        self.assertTrue(any("falling back" in line for line in self.notes))

    def test_strict_mode_stops_on_invalid_structured_output(self):
        with self.assertRaisesRegex(RuntimeError, "Structured LLM output failed"):
            analyse_target(
                "example.test", "synthetic scan evidence", settings=self.settings("strict"),
                ports=self.ports,
            )
        self.structured.assert_called_once()
        self.dispatch.assert_not_called()

    def test_off_mode_skips_structured_request(self):
        result = analyse_target(
            "example.test", "synthetic scan evidence", settings=self.settings("off"),
            ports=self.ports,
        )
        self.assertEqual(result["risk_level"], "LOW")
        self.structured.assert_not_called()
        self.dispatch.assert_not_called()

    def test_passive_mode_does_not_parse_or_dispatch_untrusted_tool_directives(self):
        self.model.return_value = (
            "[TOOL: nmap -sV example.test]\nRISK_LEVEL: LOW\nSUMMARY: Passive inventory"
        )
        self.extract.side_effect = AssertionError("Cannot interpret model tools in passive mode")
        result = analyse_target(
            "example.test", "synthetic RDAP inventory",
            settings=self.settings("off"), ports=self.ports, passive_only=True,
        )
        self.assertEqual(result["risk_level"], "LOW")
        self.extract.assert_not_called()
        self.dispatch.assert_not_called()


    def test_model_search_is_disabled_by_default_even_with_injected_query(self):
        self.model.return_value = "RISK_LEVEL: LOW\\nSUMMARY: no findings"
        self.extract.return_value = [
            ("SEARCH", "internal.example.local token=SECRET-EXAMPLE"),
        ]
        result = analyse_target(
            "example.test", "synthetic secrets", settings=self.settings("off"),
            ports=self.ports,
        )
        self.assertEqual(result["risk_level"], "LOW")
        self.dispatch.assert_not_called()
        self.assertTrue(any("web search disabled" in item for item in self.notes))

    def test_opted_in_model_search_only_dispatches_public_cve_ids(self):
        settings = load_settings(root=self.root, env={
            "PENX_STRUCTURED_OUTPUT": "off",
            "PENX_CVE_DISCOVERY": "off",
            "PENX_VERIFY_SOURCES": "off",
            "PENX_MAX_LOOPS": "1",
            "PENX_LLM_URL": "http://localhost:1234",
            "PENX_ALLOW_MODEL_WEB_SEARCH": "on",
        })
        self.model.return_value = "RISK_LEVEL: LOW\\nSUMMARY: no findings"
        self.extract.side_effect = lambda _response: [
            ("SEARCH", "internal.example.local token=SECRET-EXAMPLE"),
            ("SEARCH", "CVE-2024-6387"),
        ]
        self.dispatch = Mock(return_value="[SEARCH RESULT] synthetic only")
        self.ports.run_tool_calls = self.dispatch
        with self.assertRaisesRegex(RuntimeError, "after its tool budget"):
            analyse_target("example.test", "fixture", settings=settings,
                           ports=self.ports)
        self.dispatch.assert_called_once()
        self.assertEqual(
            self.dispatch.call_args.args[0],
            [("SEARCH", "CVE-2024-6387")],
        )
        self.assertTrue(any("web query blocked" in item for item in self.notes))


if __name__ == "__main__":
    unittest.main()
