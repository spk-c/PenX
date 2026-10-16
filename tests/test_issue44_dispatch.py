"""Regression tests for issue #44: LLM tool dispatch and CLI safety."""
from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from penx_app.storage import db
import llm
import penx


class ToolDispatchTests(unittest.TestCase):
    def test_none_tool_output_does_not_abort_assessment(self):
        with patch("llm.run_tool_by_command", return_value=None), \
             patch("llm.summarize_tool_output", side_effect=lambda text: text):
            result = llm.run_tool_calls(
                [("TOOL", "nmap example.test")], authorized_target="example.test",
                raw_collector=[],
            )
        self.assertIn("Tool returned no output", result)

    def test_distinct_commands_reach_authorization_even_with_same_adapter(self):
        responses = [
            "[TOOL: nmap -sV example.test]\n"
            "[TOOL: nmap -p 80 example.test]\nRISK_LEVEL: UNKNOWN",
            "RISK_LEVEL: LOW\nSUMMARY: The model has reviewed tool results.",
        ]
        with patch("llm.MAX_TOOL_LOOPS", 1), \
             patch("llm.ask_llm", side_effect=responses), \
             patch("llm.discover", return_value={"candidates": []}), \
             patch("llm.format_report", return_value=""), \
             patch("llm.load_correction_rules", return_value=""), \
             patch("llm.self_review", return_value={
                 "review": "", "flags": [], "adjusted_risk": ""}), \
             patch("llm.STRUCTURED_MODE", "off"), \
             patch("llm.VERIFY_SOURCES", False), \
             patch("llm.run_tool_calls", return_value="Two tool requests inspected") as run, \
             patch("llm.verify_findings", side_effect=lambda x, *_a, **_kw: x):
            result = llm.analyse_target("example.test", "offline evidence")
        self.assertEqual(result["risk_level"], "LOW")
        calls = run.call_args.args[0]
        self.assertEqual(calls, [
            ("TOOL", "nmap -sV example.test"),
            ("TOOL", "nmap -p 80 example.test"),
        ])

    def test_distinct_dispatch_is_capped(self):
        responses = [
            "\n".join(f"[SEARCH: CVE-2024-{n:04d}]" for n in range(20)),
            "RISK_LEVEL: LOW\nSUMMARY: Checked evidence.",
        ]
        with patch("llm.MAX_TOOL_LOOPS", 1), \
             patch("llm.ask_llm", side_effect=responses), \
             patch("llm.discover", return_value={"candidates": []}), \
             patch("llm.format_report", return_value=""), \
             patch("llm.load_correction_rules", return_value=""), \
             patch("llm.self_review", return_value={
                 "review": "", "flags": [], "adjusted_risk": ""}), \
             patch("llm.STRUCTURED_MODE", "off"), \
             patch("llm.VERIFY_SOURCES", False), \
             patch("llm.run_tool_calls", return_value="Local mock output") as run, \
             patch("llm.verify_findings", side_effect=lambda x, *_a, **_kw: x):
            llm.analyse_target("example.test", "offline evidence")
        self.assertLessEqual(len(run.call_args.args[0]), 8)


class CorrectionAndMenuTests(unittest.TestCase):
    def test_correction_with_comma_remains_intact_in_fallback_prompt(self):
        from penx_app.storage import db_backend
        with tempfile.TemporaryDirectory() as temp, \
             patch.object(db_backend, "DB_ENGINE", "sqlite"), \
             patch.object(db_backend, "DB_PATH", str(Path(temp) / "test.db")), \
             patch("penx_app.config.DB_ENGINE", "sqlite"):
            session = db.create_session("example.test")
            vuln = db.save_vulnerability(session, "Test", "low", "80", "http", "description")
            db.save_correction(session, vuln, "hallucination",
                               "original", "", "Comma, retained in example")
            rules = llm.load_correction_rules()
        self.assertIn("Comma, retained in example", rules)

    def test_invalid_correction_field_is_rejected_before_db_write(self):
        correction = (5, 21, 7, "verified", "original", "corrected", "reason", "time")
        with patch("penx.get_corrections", return_value=[correction]), \
             patch("penx.prompt", side_effect=["9", "5", "not_a_field", "12"]), \
             patch("penx.edit_correction") as edit, \
             patch("penx.error") as error:
            penx.edit_delete_menu(21)
        edit.assert_not_called()
        error.assert_called()

    def test_correction_invalid_enum_does_not_crash_menu(self):
        correction = (5, 21, 7, "verified", "original", "corrected", "reason", "time")
        with patch("penx.get_corrections", return_value=[correction]), \
             patch("penx.prompt", side_effect=["9", "5", "status", "bad-status", "12"]), \
             patch("penx.edit_correction", side_effect=ValueError("Invalid status")) as edit, \
             patch("penx.error") as error:
            penx.edit_delete_menu(21)
        edit.assert_called_once()
        error.assert_called()

    def test_full_session_delete_needs_two_confirmations(self):
        with patch("penx.prompt", side_effect=["11", "12"]), \
             patch("penx.confirm", side_effect=[True, False]) as confirm, \
             patch("penx.delete_full_session") as delete:
            penx.edit_delete_menu(21)
        self.assertEqual(confirm.call_count, 2)
        delete.assert_not_called()

        with patch("penx.prompt", return_value="11"), \
             patch("penx.confirm", side_effect=[True, True]) as confirm, \
             patch("penx.delete_full_session") as delete:
            penx.edit_delete_menu(21)
        confirm.assert_called()
        delete.assert_called_once_with(21)


if __name__ == "__main__":
    unittest.main(verbosity=2)
