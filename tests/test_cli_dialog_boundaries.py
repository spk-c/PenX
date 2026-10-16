"""GUI-compatibility contracts for extracted history and edit dialogs."""
import inspect
import unittest
from unittest.mock import Mock, patch
import penx
from penx_app.cli import history_dialog, session_edit_dialog


class DialogBoundaries(unittest.TestCase):
    def test_public_wrappers_preserve_existing_monkeypatch_interfaces(self):
        data = {
            "history": (4, "example.test", "today", "active"),
            "summary": (1, 4, "raw", "review", "LOW", "fixture", "today"),
            "vulns": [],
        }
        with patch("penx.get_all_history", return_value=[(4, "example.test", "today", "active")]), \
             patch("penx.get_session", return_value=data), \
             patch("penx.prompt", side_effect=["4", "0"]), \
             patch("penx.print_history"), patch("penx.print_session"), \
             patch("penx.existing_reports", return_value={}), \
             patch("penx.warn") as warn:
            self.assertIsNone(penx.view_history())
        self.assertFalse(any("not found" in str(c) for c in warn.call_args_list))

    def test_correction_dialog_uses_patched_scoped_operations(self):
        record = (12, 4, 2, "hallucination", "", "", "reason", "now")
        with patch("penx.get_corrections", return_value=[record]), \
             patch("penx.prompt", side_effect=["10", "12", "12"]), \
             patch("penx.confirm", return_value=True), \
             patch("penx.delete_correction", return_value=True) as delete:
            penx.edit_delete_menu(4)
        delete.assert_called_once_with(12, sl_no=4)

    def test_extracted_dialogs_do_not_import_direct_storage_or_sql(self):
        for module in (history_dialog, session_edit_dialog):
            with self.subTest(module=module.__name__):
                text = inspect.getsource(module)
                self.assertNotIn("from penx_app.storage", text)
                self.assertNotIn("SELECT ", text)
                self.assertNotIn("INSERT INTO ", text)


if __name__ == "__main__":
    unittest.main()
