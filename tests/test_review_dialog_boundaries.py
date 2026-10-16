"""External review menus preserve CLI routing and injectable dependencies."""
import unittest
from unittest.mock import patch
import penx
from penx_app.cli import evaluation_dialog


class ReviewDialogTests(unittest.TestCase):
    def test_eval_export_uses_patched_repository_functions(self):
        with patch("penx.get_all_history", return_value=[
            (17, "example.test", "today", "active")]), \
             patch("penx.print_history"), \
             patch("penx.prompt", return_value="17"), \
             patch("penx.export_eval_package", return_value="fixture-eval.md") as export, \
             patch("builtins.input", return_value=""), \
             patch("penx.success") as success:
            penx.review_menu_choice("3")
        export.assert_called_once_with(17)
        self.assertTrue(any("fixture-eval.md" in str(c) for c in success.call_args_list))

    def test_import_forwards_original_multiline_review(self):
        source = "EVAL: Synthetic finding\nVERDICT: valid"
        with patch("penx.prompt", side_effect=["17", "external-reviewer"]), \
             patch("builtins.input", side_effect=[
                 "EVAL: Synthetic finding", "VERDICT: valid", "END", ""]), \
             patch("penx.parse_evaluation_response", return_value=[4]) as importer:
            penx.review_menu_choice("4")
        importer.assert_called_once_with(17, "external-reviewer", source)

    def test_distillation_declined_leaves_existing_rules_untouched(self):
        with patch("penx.get_learned_rules", return_value=[(1, "old", "fixture", "now")]), \
             patch("penx.prompt", return_value="reviewer"), \
             patch("builtins.input", side_effect=["RULE: Require evidence", "END", ""]), \
             patch("penx.parse_distilled_rules", return_value=["Require evidence"]), \
             patch("penx.confirm", return_value=False), \
             patch("penx.import_distilled_rules") as importer:
            penx.review_menu_choice("7")
        importer.assert_not_called()

    def test_review_dialog_does_not_open_a_database_directly(self):
        import inspect
        text = inspect.getsource(evaluation_dialog)
        self.assertNotIn("from penx_app.storage", text)
        self.assertNotIn("cursor()", text)


if __name__ == "__main__":
    unittest.main()
