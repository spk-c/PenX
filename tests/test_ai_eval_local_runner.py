"""PX-403 live fixture runner: synthetic-only, explicit endpoint, false-positive gates."""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
from io import StringIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import requests

from penx_app.analysis.ai_eval_local_runner import (
    PROMPT_SHA256, _prediction, run_local_benchmark,
)
from penx_app.analysis.local_review_client import ModelRefusal

FIXTURE = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "ai_eval_corpus_v1.json"


class LocalEvidenceBenchmarkTests(unittest.TestCase):
    def setUp(self):
        self.corpus = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def test_local_request_never_exposes_rubric_labels_or_ground_truth_quotes(self):
        calls = []

        def fake(messages, **kwargs):
            calls.append((messages, kwargs))
            self.assertEqual(kwargs["model"], "local-model")
            self.assertEqual(kwargs["timeout"], 30)
            self.assertEqual([m["role"] for m in messages], ["system", "user"])
            self.assertNotIn("supported", messages[1]["content"])
            self.assertNotIn("expected", messages[1]["content"])
            req = json.loads(messages[1]["content"])
            self.assertEqual(set(req), {"candidate_claim_ids", "untrusted_observations"})
            evidence = req["untrusted_observations"]
            if "Strict-Transport-Security:" in evidence:
                return json.dumps({"findings": [{"id": "hsts-present", "quote":
                    "Strict-Transport-Security: max-age=31536000"}]})
            if "443/tcp" in evidence:
                return json.dumps({"findings": [{"id": "port-open", "quote": "443/tcp open https"}]})
            if "v=spf1" in evidence:
                return json.dumps({"findings": [{"id": "spf-record-present", "quote": "v=spf1 -all"}]})
            return '{"findings": []}'

        report = run_local_benchmark(
            self.corpus, endpoint="http://127.0.0.1:8080", model="local-model",
            timeout=30, client=fake, clock=lambda: 0)
        self.assertEqual(len(calls), 4)
        self.assertEqual(report["true_positive_anchors"], 3)
        self.assertEqual(report["false_positive_or_unanchored_claims"], 0)
        self.assertEqual(report["missing_supported_anchors"], 0)
        self.assertEqual(report["precision"], 1)
        self.assertEqual(report["recall"], 1)
        self.assertEqual(report["local_endpoint_completions"], 4)
        self.assertFalse(report["model_identity_verified"])
        self.assertFalse(report["real_model_executed"])
        self.assertEqual(report["live_prompt_sha256"], PROMPT_SHA256)
        self.assertEqual(report["requested_model_sha256"], sha256(b"local-model").hexdigest())
        text = json.dumps(report)
        for forbidden in ("v=spf1", "Strict-Transport-Security:", "443/tcp", "example.test"):
            self.assertNotIn(forbidden, text)

    def test_hallucination_is_counted_not_dropped(self):
        def fake(*_, **__):
            return json.dumps({"findings": [
                {"id": "remote-code-execution", "quote": "shell access granted"}]})
        report = run_local_benchmark(
            self.corpus, endpoint="http://localhost:8080", model="local-model",
            client=fake, clock=lambda: 0)
        self.assertEqual(report["false_positive_or_unanchored_claims"], 4)
        self.assertEqual(report["unsupported_or_unknown_claims"], 4)
        self.assertEqual(report["missing_supported_anchors"], 3)
        self.assertEqual(report["precision"], 0)
        self.assertEqual(report["recall"], 0)

    def test_refusal_timeout_and_invalid_json_are_not_clean_negative_cases(self):
        responses = iter([ModelRefusal("no"), requests.Timeout(),
                          '{"findings":[{"id":"bad","quote": "ok"}, {"id":"bad","quote":"ok"}]}',
                          '{"findings":[]}' ])

        def fake(*_, **__):
            value = next(responses)
            if isinstance(value, Exception):
                raise value
            return value
        report = run_local_benchmark(
            self.corpus, endpoint="http://localhost", model="local",
            client=fake, clock=lambda: 0)
        self.assertEqual(report["local_endpoint_completions"], 1)
        self.assertEqual(report["failure_cases"],
                         {"invalid_json": 1, "refusal": 1, "timeout": 1})
        self.assertEqual(report["missing_supported_anchors"], 3)

    def test_endpoint_and_budget_refused_before_model(self):
        client = Mock()
        for endpoint, model, timeout, budget in [
            ("https://remote.example", "local", 20, 60),
            ("http://localhost", "auto", 20, 60),
            ("http://127.0.0.1", "local", 2, 60),
            ("http://127.0.0.1", "local", 20, 601),
            ("http://127.0.0.1", "local", 20, True),
        ]:
            with self.subTest(endpoint=endpoint, model=model), self.assertRaises(ValueError):
                run_local_benchmark(self.corpus, endpoint=endpoint, model=model,
                                    timeout=timeout, batch_budget=budget, client=client)
        oversized = deepcopy(self.corpus)
        oversized["cases"] = [deepcopy(oversized["cases"][0]) for _ in range(21)]
        for index, case in enumerate(oversized["cases"]):
            case["id"] = "newcase-" + str(index)
        with self.assertRaises(ValueError):
            run_local_benchmark(oversized, endpoint="http://localhost",
                                model="local", client=client)
        client.assert_not_called()

    def test_exhausted_budget_marks_unattempted_cases_as_timeout(self):
        ticks = iter([0, 0, 601, 601, 601])
        client = Mock(return_value='{"findings":[]}')
        report = run_local_benchmark(self.corpus, endpoint="http://127.0.0.1",
                                      model="local", clock=lambda: next(ticks),
                                      client=client)
        self.assertEqual(report["local_endpoint_requests"], 1)
        self.assertEqual(report["failure_cases"]["timeout"], 3)
        self.assertEqual(client.call_count, 1)

    def test_invalid_responses_fail_closed_without_discarding_hallucinations(self):
        for bad in (
            '{"findings":[{"id":"x","quote":"a","other":"tool"}]}',
            '{"findings":[{"id":"x","quote":"a"},{"id":"x","quote":"b"}]}',
            '{"findings":[],"findings":[]}',
            '{"findings": [NaN]}', '{"findings": "not-array"}',
            '{"findings": []}' + "x" * 70_000,
        ):
            with self.subTest(bad=bad[:40]), self.assertRaises(ValueError):
                _prediction(bad)
        self.assertEqual(_prediction('{"findings":[{"id":"invented-cve","quote":"not in original"}]}'),
                         [{"id": "invented-cve", "quote": "not in original"}])

    def test_transport_failure_is_not_reported_as_model_accuracy(self):
        client = Mock(side_effect=requests.ConnectionError("do not print this"))
        with self.assertRaisesRegex(ValueError, "endpoint unavailable"):
            run_local_benchmark(self.corpus, endpoint="http://127.0.0.1",
                                model="local", client=client)

    def test_cli_preflight_no_requests_and_aggregate_only(self):
        from scripts.benchmark_local_ai import main
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "metric.json"
            with patch("scripts.benchmark_local_ai.run_local_benchmark") as runner:
                runner.return_value = {"local_endpoint_completions": 4, "cases": 4}
                self.assertEqual(main(["--endpoint", "http://127.0.0.1:8080",
                                       "--model", "model", "--output", str(target)]), 0)
                self.assertTrue(target.is_file())
                self.assertNotIn("Strict-Transport-Security:",
                                 target.read_text(encoding="utf-8"))
                runner.assert_called_once()
                self.assertEqual(main(["--endpoint", "http://127.0.0.1:8080",
                                       "--model", "model", "--output", str(target)]), 2)
                self.assertEqual(main(["--endpoint", "http://example.test",
                                       "--model", "model"]), 2)
                runner.assert_called_once()

    def test_explicit_provider_refusal_uses_typed_exception(self):
        from penx_app.analysis.local_review_client import request_review

        class FakeResponse:
            status_code = 200
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def iter_content(self, **kwargs):
                yield json.dumps({"choices": [{"finish_reason": "stop", "message": {
                    "role": "assistant", "refusal": "blocked", "content": "secret"}}]}).encode()

        class FakeSession:
            trust_env = True
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def post(self, *args, **kwargs):
                self.assert_no_redirects = not kwargs["allow_redirects"]
                return FakeResponse()

        with self.assertRaises(ModelRefusal):
            request_review([], endpoint="http://127.0.0.1",
                           model="local", schema={"type": "object"},
                           session_factory=FakeSession)


if __name__ == "__main__":
    unittest.main()
