"""Regression coverage for open issue #39 and the overlap with #40/#4."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import requests
import penx


class ScanLifecycleTests(unittest.TestCase):
    def _scan_mocks(self):
        return [
            patch("penx.prompt", return_value="example.test"),
            patch("penx.llm_auth_preflight", return_value=True),
            patch("penx.get_all_history", return_value=[]),
            patch("penx.interactive_tool_run", return_value="Nmap: 443/tcp open https"),
            patch("penx.recon_has_evidence", return_value=True),
            patch("penx.create_session", return_value=79),
        ]

    def test_network_error_rolls_back_pending_session(self):
        from contextlib import ExitStack
        with ExitStack() as stack:
            for p in self._scan_mocks():
                stack.enter_context(p)
            stack.enter_context(patch("penx.analyse_target",
                                      side_effect=requests.exceptions.ConnectionError("offline")))
            preserve = stack.enter_context(
                patch("penx.preserve_failed_recon", return_value=Path("evidence.txt")))
            cleanup = stack.enter_context(patch("penx.delete_full_session"))
            self.assertIs(penx.new_scan(), False)
        preserve.assert_called_once_with(79, "Nmap: 443/tcp open https")
        cleanup.assert_called_once_with(79)

    def test_cleanup_error_does_not_replace_initial_network_failure(self):
        from contextlib import ExitStack
        with ExitStack() as stack:
            for p in self._scan_mocks():
                stack.enter_context(p)
            stack.enter_context(patch("penx.analyse_target",
                                      side_effect=requests.exceptions.Timeout("offline")))
            stack.enter_context(patch("penx.preserve_failed_recon",
                                      side_effect=OSError("permission denied")))
            cleanup = stack.enter_context(
                patch("penx.delete_full_session", side_effect=OSError("DB locked")))
            warn = stack.enter_context(patch("penx.warn"))
            self.assertIs(penx.new_scan(), False)
        cleanup.assert_called_once_with(79)
        self.assertTrue(any("pending session" in str(c) for c in warn.call_args_list))

    def test_auth_failure_and_duplicate_cancel_return_false(self):
        with patch("penx.prompt", return_value="example.test"), \
             patch("penx.llm_auth_preflight", return_value=False):
            self.assertIs(penx.new_scan(), False)
        with patch("penx.prompt", return_value="example.test"), \
             patch("penx.llm_auth_preflight", return_value=True), \
             patch("penx.get_all_history", return_value=[(5, "example.test", "date", "active")]), \
             patch("penx.confirm", return_value=False):
            self.assertIs(penx.new_scan(), False)

    def test_committed_scan_returns_true(self):
        from contextlib import ExitStack
        with ExitStack() as stack:
            for p in self._scan_mocks():
                stack.enter_context(p)
            stack.enter_context(patch("penx.analyse_target", return_value={"risk_level": "LOW"}))
            stack.enter_context(patch("penx.save_assessment", return_value={
                "vulnerabilities": 0, "recommendations": 0, "rejected": 0,
                "corrections": 0, "exploits": 0
            }))
            stack.enter_context(patch("penx.generate_session_reports", return_value={}))
            stack.enter_context(patch("penx.get_session", return_value={"history": (79, "example.test", "now", "active")}))
            stack.enter_context(patch("penx.print_session"))
            stack.enter_context(patch("penx_app.application.risk_assessment.assessment_for_session", return_value=[]))
            stack.enter_context(patch("penx_app.cli.assessment_ui.automatic_regression_check"))
            stack.enter_context(patch("penx.confirm", return_value=False))
            self.assertIs(penx.new_scan(), True)
            # Minimal mocked model responses must still be annotatable.
            saved = penx.save_assessment.call_args.args[1]
            self.assertIn("[SCAN COVERAGE]", saved["full_response"])

    def test_evidence_collision_fallback_does_not_overwrite(self):
        with tempfile.TemporaryDirectory() as temp, patch("penx.APP_ROOT", Path(temp)):
            first = penx.preserve_failed_recon(9, "first failure")
            second = penx.preserve_failed_recon(9, "second failure")
            third = penx.preserve_failed_recon(9, "third failure")
            self.assertEqual(len({first, second, third}), 3)
            self.assertEqual(first.read_text(encoding="utf-8"), "first failure")
            self.assertEqual(second.read_text(encoding="utf-8"), "second failure")
            self.assertEqual(third.read_text(encoding="utf-8"), "third failure")


class CLISafetyTests(unittest.TestCase):
    def test_invalid_vulnerability_column_is_never_sent_to_db(self):
        vulnerabilities = [(7, 20, "finding", "low", "443", "https")]
        with patch("penx.get_vulnerabilities", return_value=vulnerabilities), \
             patch("penx.prompt", side_effect=["1", "7", "DROP TABLE history", "12"]), \
             patch("penx.edit_vulnerability") as edit, \
             patch("penx.error") as error:
            penx.edit_delete_menu(20)
        edit.assert_not_called()
        error.assert_called()

    def test_invalid_exploit_column_is_never_sent_to_db(self):
        exploits = [(3, 20, "test", "Nmap", "", "not attempted")]
        with patch("penx.get_exploits", return_value=exploits), \
             patch("penx.prompt", side_effect=["3", "3", "invalid_sql", "12"]), \
             patch("penx.edit_exploit") as edit, \
             patch("penx.error") as error:
            penx.edit_delete_menu(20)
        edit.assert_not_called()
        error.assert_called()

    def test_ctrl_c_and_eof_leave_main_menu_without_traceback(self):
        for exception in (KeyboardInterrupt, EOFError):
            with self.subTest(exception=exception.__name__), \
                 patch("penx.banner"), \
                 patch("penx.prompt", side_effect=exception):
                self.assertIsNone(penx.main_menu())


class MaintenanceTests(unittest.TestCase):
    def test_mariadb_migrations_have_order_and_pending_status(self):
        root = Path(__file__).resolve().parents[1]
        guide = (root / "migrations" / "README.md").read_text(encoding="utf-8")
        filenames = [f"{i:03d}_{name}.sql" for i, name in [
            (1, "baseline"), (2, "evaluations"), (3, "confidence"),
            (4, "learned_rules"), (5, "runtime_compat"),
        ]]
        for name in filenames:
            self.assertTrue((root / "migrations" / name).is_file())
            self.assertIn(name, guide)
        self.assertEqual([guide.index(name) for name in filenames],
                         sorted(guide.index(name) for name in filenames))
        baseline = (root / "migrations/001_baseline.sql").read_text(encoding="utf-8")
        for table in ("history", "vulnerabilities", "fixes", "exploits_attempted",
                      "summary", "corrections"):
            self.assertIn("CREATE TABLE IF NOT EXISTS " + table, baseline)
        compat = (root / "migrations/005_runtime_compat.sql").read_text(encoding="utf-8")
        self.assertIn("ADD COLUMN IF NOT EXISTS status", compat)

    def test_demo_action_versions_are_current(self):
        yml = (Path(__file__).resolve().parents[1] /
               ".github/workflows/record-localhost-demo.yml").read_text(encoding="utf-8")
        for action in ("checkout", "setup-python", "upload-artifact"):
            self.assertIn(f"actions/{action}@v7", yml)


if __name__ == "__main__":
    unittest.main(verbosity=2)
