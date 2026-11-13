"""PX-404 second-pass critic: source quotes, missing proof and no tool execution.

All requests are mock local LLM replies to synthetic reports. No live scan.
"""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from jsonschema import ValidationError

from penx_app.application.local_review import create_review, main
from penx_app.domain.local_review import review_sources
from penx_app.domain.review_critic import CRITIC_SCHEMA, critic_summary, validate_critique
from tests.test_local_review import report, review


def response(judgment="disputes", quote="TEMPLATE sample | high"):
    return {"summary": "Second-pass review is advisory.", "reviews": [{
        "fingerprint": report()["findings"][0]["fingerprint"],
        "judgment": judgment,
        "rationale": "The cited observation cannot establish impact by itself.",
        "evidence_quote": quote,
    }]}


class CriticTests(unittest.TestCase):
    def setUp(self):
        self.sources = review_sources(report())
        self.primary = review()

    def test_disagreement_requires_distinct_exact_quote_from_same_source(self):
        checked = validate_critique(json.dumps(response()), self.sources, self.primary)
        result = critic_summary(checked, source_count=1)
        self.assertEqual(result["schema"], "penx-review-critic-v1")
        self.assertEqual(result["model_reported_disagreements"], 1)
        self.assertFalse(result["vulnerability_verified"])
        self.assertFalse(result["contradiction_verified"])
        self.assertTrue(result["operator_review_required"])

    def test_unknown_duplicate_and_foreign_quotes_fail(self):
        bad_cases = [
            lambda a: a["reviews"][0].update(fingerprint="penx-finding-v1:" + "f"*64),
            lambda a: a["reviews"].append(deepcopy(a["reviews"][0])),
            lambda a: a["reviews"][0].update(evidence_quote="irrelevant fabricated exploitation"),
            lambda a: a["reviews"][0].update(evidence_quote=self.primary["reviews"][0]["evidence_quote"]),
            lambda a: a["reviews"][0].update(evidence_quote=" | high"),
            lambda a: a["reviews"][0].update(judgment="confirmed"),
            lambda a: a["reviews"][0].update(command="scan external host"),
            lambda a: a["reviews"][0].update(rationale=""),
        ]
        for bad in bad_cases:
            data = response()
            bad(data)
            with self.subTest(bad=str(bad)), self.assertRaises((ValueError, ValidationError)):
                validate_critique(json.dumps(data), self.sources, self.primary)

    def test_unresolved_requires_empty_quote(self):
        data = response(judgment="unresolved", quote="")
        checked = validate_critique(json.dumps(data), self.sources, self.primary)
        self.assertEqual(critic_summary(checked, source_count=1)["model_reported_disagreements"], 0)
        data["reviews"][0]["evidence_quote"] = "TEMPLATE sample | high"
        with self.assertRaises(ValueError):
            validate_critique(json.dumps(data), self.sources, self.primary)

    def test_insufficient_primary_cannot_be_disputed_as_a_positive_claim(self):
        primary = deepcopy(self.primary)
        primary["reviews"][0].update(assessment="insufficient_evidence", evidence_quote="")
        with self.assertRaises(ValueError):
            validate_critique(json.dumps(response()), self.sources, primary)

    def test_malformed_duplicate_keys_and_oversize_fail_closed(self):
        for response_text in ('{"summary":"x","summary":"y","reviews":[]}',
                              '{"summary":NaN,"reviews":[]}',
                              "x" * 65537):
            with self.assertRaises((ValueError, ValidationError)):
                validate_critique(response_text, self.sources, self.primary)

    def test_opt_in_critic_uses_only_prior_sources_and_never_changes_report(self):
        original = report()
        before = deepcopy(original)
        client = Mock(side_effect=[json.dumps(review()), json.dumps(response())])
        result = create_review(
            original, endpoint="http://127.0.0.1:8080", model="investigator",
            critic_model="critic", client=client)
        self.assertEqual(original, before)
        self.assertEqual(client.call_count, 2)
        self.assertEqual([call.kwargs["model"] for call in client.call_args_list],
                         ["investigator", "critic"])
        self.assertEqual(client.call_args_list[1].kwargs["schema"], CRITIC_SCHEMA)
        messages = client.call_args_list[1].args[0]
        data = json.loads(messages[1]["content"])
        self.assertEqual(set(data), {"untrusted_observations", "untrusted_first_pass_draft"})
        self.assertNotIn("allowed_scanner_keys", messages[1]["content"])
        self.assertNotIn("tools", client.call_args_list[1].kwargs)
        self.assertEqual(result["state"], "draft-unverified")
        self.assertEqual(result["critic"]["model_reported_disagreements"], 1)
        self.assertFalse(result["critic"]["vulnerability_verified"])

    def test_absent_critic_flag_retains_original_single_request_and_shape(self):
        client = Mock(return_value=json.dumps(review()))
        result = create_review(report(), endpoint="http://127.0.0.1:8080",
                               model="investigator", client=client)
        client.assert_called_once()
        self.assertNotIn("critic", result)

    def test_critic_invalid_response_prevents_draft_publication(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root) / "synthetic-report.json"
            source.write_text(json.dumps(report()), encoding="utf-8")
            client = [json.dumps(review()), json.dumps(response(quote="completely invented quote"))]
            with patch("penx_app.application.local_review.request_review", side_effect=client) as ask:
                self.assertEqual(main([str(source), "--model", "investigator",
                    "--critic-model", "critic", "--output", root]), 1)
                self.assertEqual(ask.call_count, 2)
            self.assertEqual([p.name for p in Path(root).iterdir()], [source.name])

    def test_critic_cli_writes_additive_unverified_separate_draft(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root) / "synthetic-report.json"
            source.write_text(json.dumps(report()), encoding="utf-8")
            with patch("penx_app.application.local_review.request_review",
                       side_effect=[json.dumps(review()), json.dumps(response())]):
                self.assertEqual(main([str(source), "--model", "investigator",
                    "--critic-model", "critic", "--output", root]), 0)
            saved = json.loads((Path(root) / "penx_review.json").read_text(encoding="utf-8"))
            self.assertEqual(saved["critic_model"], "critic")
            self.assertEqual(saved["critic"]["state"], "second-pass-draft-unverified")
            self.assertFalse(saved["critic"]["vulnerability_verified"])
            self.assertNotIn("confirmed", json.dumps(saved["critic"]))

    def test_invalid_critic_model_fails_before_any_network(self):
        client = Mock()
        with self.assertRaises(ValueError):
            create_review(report(), endpoint="http://127.0.0.1", model="investigator",
                          critic_model="auto", client=client)
        client.assert_not_called()


if __name__ == "__main__":
    unittest.main()
