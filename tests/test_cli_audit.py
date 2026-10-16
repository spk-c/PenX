"""Regressions for CLI audit: input parsing and preserved model evidence."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import penx


class CliAuditTests(unittest.TestCase):
    def test_confirm_accepts_localized_affirmative(self):
        for answer in ("y", "yes", "j", "ja", "JA"):
            with self.subTest(answer=answer), patch("penx.prompt", return_value=answer):
                self.assertTrue(penx.confirm("Continue?"))
        for answer in ("n", "", "no"):
            with self.subTest(answer=answer), patch("penx.prompt", return_value=answer):
                self.assertFalse(penx.confirm("Continue?"))

    def test_failed_assessment_preserved_without_overwriting(self):
        with tempfile.TemporaryDirectory() as tmp, patch("penx.APP_ROOT", Path(tmp)):
            first = penx.preserve_failed_assessment(42, {"full_response": "first", "risk_level": "LOW"})
            second = penx.preserve_failed_assessment(42, {"full_response": "second"})
            self.assertNotEqual(first, second)
            self.assertEqual(json.loads(first.read_text(encoding="utf-8"))["full_response"], "first")
            self.assertEqual(json.loads(second.read_text(encoding="utf-8"))["full_response"], "second")


    def test_scan_recon_exception_does_not_create_pending_session(self):
        with patch("penx.prompt", return_value="example.test"), \
             patch("penx.llm_auth_preflight", return_value=True), \
             patch("penx.get_all_history", return_value=[]), \
             patch("penx.interactive_tool_run", side_effect=OSError("scanner unavailable")), \
             patch("penx.create_session") as reserve, \
             patch("penx.warn") as warning:
            self.assertFalse(penx.new_scan())
        reserve.assert_not_called()
        self.assertTrue(any("Recon failed" in str(c) for c in warning.call_args_list))

    def test_failed_database_save_preserves_assessment_before_cleanup(self):
        from contextlib import ExitStack
        with ExitStack() as stack:
            for patcher in (
                patch("penx.prompt", return_value="example.test"),
                patch("penx.llm_auth_preflight", return_value=True),
                patch("penx.get_all_history", return_value=[]),
                patch("penx.interactive_tool_run", return_value="Nmap: 80/tcp open http"),
                patch("penx.recon_has_evidence", return_value=True),
                patch("penx.create_session", return_value=42),
                patch("penx.analyse_target", return_value={
                    "risk_level": "LOW", "full_response": "fixture LLM"}),
                patch("penx.save_assessment", side_effect=OSError("database locked")),
                patch("penx.preserve_failed_recon", return_value="fixture.txt"),
            ):
                stack.enter_context(patcher)
            save_backup = stack.enter_context(patch("penx.preserve_failed_assessment"))
            cleanup = stack.enter_context(patch("penx.delete_full_session"))
            self.assertIs(penx.new_scan(), False)
        self.assertEqual(save_backup.call_args.args[0], 42)
        self.assertIn("fixture LLM", save_backup.call_args.args[1]["full_response"])
        cleanup.assert_called_once_with(42)

    def test_committed_scan_survives_display_error(self):
        from contextlib import ExitStack
        with ExitStack() as stack:
            for patcher in (
                patch("penx.prompt", return_value="example.test"),
                patch("penx.llm_auth_preflight", return_value=True),
                patch("penx.get_all_history", return_value=[]),
                patch("penx.interactive_tool_run", return_value="Nmap: 80/tcp open http"),
                patch("penx.recon_has_evidence", return_value=True),
                patch("penx.create_session", return_value=42),
                patch("penx.analyse_target", return_value={"risk_level": "LOW"}),
                patch("penx.generate_session_reports", return_value={}),
                patch("penx.get_session", side_effect=OSError("display DB failure")),
            ):
                stack.enter_context(patcher)
            write = stack.enter_context(patch("penx.save_assessment", return_value={
                "vulnerabilities": 0, "recommendations": 0, "corrections": 0, "exploits": 0}))
            warning = stack.enter_context(patch("penx.warn"))
            self.assertIs(penx.new_scan(), True)
        write.assert_called_once()
        self.assertTrue(any("already" not in str(c) and "follow-up display/review failed" in str(c)
                            for c in warning.call_args_list))

    def test_scoped_delete_never_claims_noop_success(self):
        with patch("penx.warn") as warning, patch("penx.success") as success:
            penx._apply_delete("Fix", lambda: False)
        warning.assert_called_once()
        success.assert_not_called()
        with patch("penx.error") as error, patch("penx.success") as success:
            penx._apply_delete("Fix", lambda: (_ for _ in ()).throw(OSError("DB down")))
        error.assert_called_once()
        success.assert_not_called()


if __name__ == "__main__":
    unittest.main()
