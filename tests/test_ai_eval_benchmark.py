"""Offline PX-403 synthetic AI evaluation: status, provenance and no-network."""
from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from io import StringIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from penx_app.analysis.ai_eval_benchmark import (
    read_bounded_json, score_predictions,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"


class OfflineAiEvalTests(unittest.TestCase):
    def setUp(self):
        self.corpus = json.loads(
            (FIXTURES / "ai_eval_corpus_v1.json").read_text(encoding="utf-8"))
        self.predictions = json.loads(
            (FIXTURES / "ai_eval_predictions_v1.json").read_text(encoding="utf-8"))

    def test_deterministic_fixture_scores_and_failures(self):
        report = score_predictions(self.corpus, self.predictions)
        self.assertEqual(report["schema"], "penx-ai-eval-report-v1")
        self.assertEqual(report["mode"], "offline-labelled-fixture")
        self.assertEqual(report["case_count"], 4)
        self.assertEqual(report["successful_prediction_cases"], 2)
        self.assertEqual(report["failure_cases"], {
            "invalid_json": 0, "refusal": 1, "timeout": 1})
        self.assertEqual(report["true_positive_anchors"], 2)
        self.assertEqual(report["false_positive_or_unanchored_claims"], 1)
        self.assertEqual(report["unsupported_or_unknown_claims"], 1)
        self.assertEqual(report["missing_supported_anchors"], 1)
        self.assertEqual(report["precision"], 0.6667)
        self.assertEqual(report["recall"], 0.6667)
        self.assertFalse(report["real_model_executed"])
        self.assertFalse(report["real_target_scanned"])
        self.assertEqual(report, score_predictions(self.corpus, self.predictions))
        self.assertNotIn("443/tcp", json.dumps(report))
        self.assertNotIn("remote shell confirmed", json.dumps(report))

    def test_invented_citation_fails_both_precision_and_recall(self):
        predictions = deepcopy(self.predictions)
        predictions["cases"][0]["findings"][0]["quote"] = "not an actual quote"
        report = score_predictions(self.corpus, predictions)
        self.assertEqual(report["true_positive_anchors"], 1)
        self.assertEqual(report["false_positive_or_unanchored_claims"], 2)
        self.assertEqual(report["missing_supported_anchors"], 2)

    def test_unknown_claim_counts_false_positive_not_proof(self):
        predictions = deepcopy(self.predictions)
        predictions["cases"][0]["findings"].append(
            {"id": "invented-critical-cve", "quote": "nothing observed"})
        report = score_predictions(self.corpus, predictions)
        self.assertEqual(report["unsupported_or_unknown_claims"], 2)
        self.assertEqual(report["false_positive_or_unanchored_claims"], 2)

    def test_failures_never_silently_count_as_clean_coverage(self):
        predictions = deepcopy(self.predictions)
        predictions["cases"][0]["status"] = "invalid_json"
        predictions["cases"][0]["findings"] = []
        report = score_predictions(self.corpus, predictions)
        self.assertEqual(report["failure_cases"]["invalid_json"], 1)
        self.assertEqual(report["successful_prediction_cases"], 1)
        self.assertEqual(report["true_positive_anchors"], 1)
        self.assertEqual(report["missing_supported_anchors"], 2)

    def test_noncomplete_case_cannot_claim_findings(self):
        predictions = deepcopy(self.predictions)
        predictions["cases"][0]["status"] = "refusal"
        with self.assertRaises(ValueError):
            score_predictions(self.corpus, predictions)

    def test_invalid_rubrics_and_predictions_fail_closed(self):
        cases = [
            lambda a, b: a["cases"][0]["expected"].append(
                deepcopy(a["cases"][0]["expected"][0])),
            lambda a, b: a["cases"][0]["expected"][0].update(quote="fake quote"),
            lambda a, b: a["cases"][0]["expected"][1].update(quote="unsupported"),
            lambda a, b: a["cases"][0]["expected"][0].update(supported="true"),
            lambda a, b: a["cases"][0].update(evidence=""),
            lambda a, b: a["cases"].append(deepcopy(a["cases"][0])),
            lambda a, b: b["cases"].pop(),
            lambda a, b: b["cases"][0]["findings"].append(
                deepcopy(b["cases"][0]["findings"][0])),
            lambda a, b: b["cases"][0].update(status="finished"),
            lambda a, b: b.update(prompt_sha256="0" * 64),
            lambda a, b: b["cases"][0].update(unexpected="raw"),
        ]
        for mutation in cases:
            corpus, predictions = deepcopy(self.corpus), deepcopy(self.predictions)
            mutation(corpus, predictions)
            with self.subTest(mutation=str(mutation)), self.assertRaises(ValueError):
                score_predictions(corpus, predictions)

    def test_strict_file_limits_and_duplicate_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "good.json"
            sample.write_text('{"schema":1,"schema":2}', encoding="utf-8")
            with self.assertRaises(ValueError):
                read_bounded_json(sample)
            sample.write_bytes(b"X" * (1024 * 1024 + 1))
            with self.assertRaises(ValueError):
                read_bounded_json(sample)
            sample.write_bytes(bytes([0xFF]))
            with self.assertRaises(ValueError):
                read_bounded_json(sample)
            real = root / "real.json"
            real.write_text("{}", encoding="utf-8")
            try:
                sample.unlink()
                sample.symlink_to(real)
            except (OSError, NotImplementedError):
                return
            with self.assertRaises(ValueError):
                read_bounded_json(sample)

    def test_cli_never_runs_model_network_or_scanner(self):
        from scripts.benchmark_ai_assessment import main
        output = StringIO()
        with (patch("socket.create_connection",
                    side_effect=AssertionError("no network")) as network,
              patch("subprocess.run",
                    side_effect=AssertionError("no process")) as process,
              redirect_stdout(output)):
            self.assertEqual(main([]), 0)
        network.assert_not_called()
        process.assert_not_called()
        report = json.loads(output.getvalue())
        self.assertEqual(report["true_positive_anchors"], 2)
        self.assertRegex(report["corpus_sha256"], "^[a-f0-9]{64}$")
        self.assertNotIn("example.test", output.getvalue())
        self.assertNotIn("Strict-Transport-Security:", output.getvalue())

    def test_cli_output_nonoverwriting_and_errors_redacted(self):
        from scripts.benchmark_ai_assessment import main
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / "metrics.json"
            self.assertEqual(main(["--output", str(file)]), 0)
            original = file.read_bytes()
            with redirect_stderr(StringIO()) as errors:
                self.assertEqual(main(["--output", str(file)]), 2)
                self.assertEqual(main(["--corpus", "missing-sensitive-path.json"]), 2)
            self.assertEqual(file.read_bytes(), original)
            self.assertNotIn("missing-sensitive-path", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
