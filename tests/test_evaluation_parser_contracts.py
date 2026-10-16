"""Bounded, storage-independent evaluation response parsing contracts."""
import unittest
from unittest.mock import patch

from penx_app.domain.evaluation_parser import evaluation_groups, parse_distilled_rules
from penx_app.storage import db_evals


class EvaluationParsingTests(unittest.TestCase):
    def test_markdown_labels_preserve_multiple_groups_and_multiline_evidence(self):
        text = ("**EVAL:** Scanner claim\n**VERDICT:** valid\n"
                "**EVIDENCE:** line one\nline two\n**NOTES:** review\n"
                "**EVAL:** Other claim\n**VERDICT:** hallucination\n")
        groups = evaluation_groups(text)
        self.assertEqual(len(groups), 2)
        self.assertEqual(groups[0]["EVIDENCE"], "line one\nline two")
        self.assertEqual(groups[1]["EVAL"], "Other claim")

    def test_distilled_parser_drops_echoed_source_and_duplicates(self):
        text = ("RULE: Verify every claim before reporting (source: fixture, 2026-10-15 17:00)\n"
                "RULE: Verify every claim before reporting\n"
                "RULE: short\n")
        self.assertEqual(parse_distilled_rules(text), ["Verify every claim before reporting"])
        self.assertEqual(db_evals.parse_distilled_rules(text),
                         parse_distilled_rules(text))

    def test_parsers_never_open_storage_or_execute_model(self):
        with patch.object(db_evals, "get_connection", side_effect=AssertionError("database touched")):
            self.assertEqual(evaluation_groups("EVAL: test\nVERDICT: valid")[0]["EVAL"], "test")
            self.assertEqual(parse_distilled_rules("RULE: Require supporting evidence"),
                             ["Require supporting evidence"])


if __name__ == "__main__":
    unittest.main()
