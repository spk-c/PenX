"""Regression tests for issue #58: edit menu robustness and honest write feedback."""
from __future__ import annotations

from contextlib import ExitStack
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from penx_app.storage import db
from penx_app.storage import db_backend
import penx


# name, read helper, read rows, menu inputs, edit helper, expected write arguments
MENU_CASES = (
    ("Vulnerability", "get_vulnerabilities",
     [(7, 20, "Test", "low", "443", "https")],
     ["1", "7", "description", "revised", "12"],
     "edit_vulnerability", (7, "description", "revised"), {"sl_no": 20}),
    ("Fix", "get_fixes",
     [(8, 20, 7, "old fix")],
     ["2", "8", "revised", "12"],
     "edit_fix", (8, "revised"), {"sl_no": 20}),
    ("Exploit", "get_exploits",
     [(9, 20, "Test", "Nmap", "", "old result")],
     ["3", "9", "notes", "revised", "12"],
     "edit_exploit", (9, "notes", "revised"), {"sl_no": 20}),
    ("Risk level", None, None,
     ["4", "HIGH", "12"],
     "edit_summary_risk", (20, "HIGH"), {}),
    ("Correction", "get_corrections",
     [(10, 20, 7, "verified", "original", "corrected", "old reason")],
     ["9", "10", "reason", "revised", "12"],
     "edit_correction", (10, "reason", "revised"), {"sl_no": 20}),
)


class EditMenuErrorHandlingTests(unittest.TestCase):
    def run_case(self, case, *, result=None, failure=None):
        label, getter, rows, answers, edit_name, args, kwargs = case
        with ExitStack() as stack:
            if getter:
                stack.enter_context(patch("penx." + getter, return_value=rows))
            stack.enter_context(patch("penx.prompt", side_effect=answers))
            edit = stack.enter_context(patch(
                "penx." + edit_name,
                **({"side_effect": failure} if failure is not None else {"return_value": result})))
            error = stack.enter_context(patch("penx.error"))
            warn = stack.enter_context(patch("penx.warn"))
            success = stack.enter_context(patch("penx.success"))
            penx.edit_delete_menu(20)
        edit.assert_called_once_with(*args, **kwargs)
        return label, error, warn, success

    def test_connection_errors_do_not_crash_any_edit_path(self):
        for case in MENU_CASES:
            with self.subTest(edit=case[0]):
                label, error, warn, success = self.run_case(
                    case, failure=OSError("DB locked"))
                error.assert_called_once()
                self.assertIn("Could not update " + label.lower(),
                              error.call_args.args[0])
                self.assertIn("OSError: DB locked", error.call_args.args[0])
                warn.assert_not_called()
                success.assert_not_called()

    def test_value_errors_are_reported_without_traceback(self):
        for case in MENU_CASES:
            with self.subTest(edit=case[0]):
                _, error, warn, success = self.run_case(
                    case, failure=ValueError("Invalid test value"))
                error.assert_called_once_with("Invalid test value")
                warn.assert_not_called()
                success.assert_not_called()

    def test_zero_affected_rows_never_announce_success(self):
        for case in MENU_CASES:
            with self.subTest(edit=case[0]):
                label, error, warn, success = self.run_case(case, result=False)
                error.assert_not_called()
                warn.assert_called_once()
                self.assertIn(label.lower(), warn.call_args.args[0].lower())
                success.assert_not_called()

    def test_success_requires_truthy_database_result(self):
        for case in MENU_CASES:
            with self.subTest(edit=case[0]):
                label, error, warn, success = self.run_case(case, result=True)
                error.assert_not_called()
                warn.assert_not_called()
                success.assert_called_once_with(label + " updated.")


class EditRiskDatabaseTests(unittest.TestCase):
    def test_risk_edit_returns_affected_row_status_on_sqlite(self):
        with tempfile.TemporaryDirectory() as temp, \
             patch.object(db_backend, "DB_ENGINE", "sqlite"), \
             patch.object(db_backend, "DB_PATH", str(Path(temp) / "penx.db")):
            sl_no = db.create_session("example.test")
            db.save_summary(sl_no, "test evidence", "test assessment", "LOW")
            self.assertIs(db.edit_summary_risk(sl_no, "HIGH"), True)
            self.assertIs(db.edit_summary_risk(sl_no + 999, "HIGH"), False)
            with self.assertRaises(ValueError):
                db.edit_summary_risk(sl_no, "INVALID")
            conn = db_backend.get_connection()
            try:
                cur = conn.cursor()
                cur.execute("SELECT risk_level FROM summary WHERE sl_no = %s", (sl_no,))
                self.assertEqual(cur.fetchone()[0], "HIGH")
            finally:
                conn.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
