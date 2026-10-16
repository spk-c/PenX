"""No-network smoke tests for reproducible refactor performance fixtures."""
import json
import tempfile
import unittest
from pathlib import Path

from scripts.refactor_benchmarks import (
    check_thresholds,
    export_once,
    main,
    median_and_range,
    measure,
    render_report,
    synthetic_session,
)

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"


class BenchmarksTests(unittest.TestCase):
    def test_synthetic_fixture_does_not_contain_customer_data(self):
        session = synthetic_session(3)
        self.assertEqual(session["history"][1], "example.test")
        self.assertEqual(len(session["vulns"]), 3)
        self.assertTrue(all("Fixture observation" in row[2] for row in session["vulns"]))

    def test_validates_sample_count_before_spawning_process(self):
        for count in (0, 11, -1):
            with self.subTest(count=count), self.assertRaises(ValueError):
                measure(count)

    def test_median_and_bounds(self):
        result = median_and_range([0.01, 0.03, 0.02])
        self.assertEqual(result, {"median_ms": 20.0, "min_ms": 10.0, "max_ms": 30.0})

    def test_render_report_rejects_unknown_format(self):
        with self.assertRaises(ValueError):
            render_report(tempfile.gettempdir(), "docx")

    def test_export_once_writes_nonempty_html_and_pdf(self):
        with tempfile.TemporaryDirectory() as tmp:
            sizes = export_once(tmp)
        self.assertGreater(sizes["html_bytes"], 0)
        self.assertGreater(sizes["pdf_bytes"], 0)

    def test_measure_includes_representative_export_workload(self):
        data = measure(1)
        self.assertEqual(data["schema"], "penx-refactor-benchmark-v2")
        for workload in ("html_export", "pdf_export"):
            self.assertIn(workload, data)
            self.assertGreaterEqual(data[workload]["median_ms"], 0)
        self.assertGreater(data["export_bytes"]["html_bytes"], 0)
        self.assertGreater(data["export_bytes"]["pdf_bytes"], 0)

    def test_check_thresholds_flags_violations_and_missing_workloads(self):
        data = {"a": {"median_ms": 120.0}, "b": {"median_ms": 5.0}}
        self.assertEqual(
            check_thresholds(data, {"a": 100, "b": 10, "c": 10}),
            ["a: median 120.0 ms exceeds calibrated limit 100 ms",
             "c: workload missing from benchmark output"])
        self.assertEqual(check_thresholds(data, {"a": 120, "b": 10}), [])


class ThresholdGateTests(unittest.TestCase):
    def test_check_thresholds_passes_with_calibrated_file(self):
        thresholds = json.loads(
            (SCRIPTS / "benchmark_thresholds.json").read_text(encoding="utf-8"))
        data = measure(1)
        self.assertEqual(check_thresholds(data, thresholds["limits"]), [])

    def test_main_fails_when_threshold_exceeded(self):
        with tempfile.TemporaryDirectory() as tmp:
            threshold_path = Path(tmp) / "thresholds.json"
            threshold_path.write_text(json.dumps({
                "limits": {"launcher_version": 0.0001},
            }), encoding="utf-8")
            output_path = Path(tmp) / "result.json"
            self.assertEqual(
                main(["--runs", "1", "--check-thresholds", str(threshold_path),
                      "--output", str(output_path)]), 1)
            result = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertFalse(result["threshold_check"]["passed"])
            self.assertTrue(any(
                line.startswith("launcher_version")
                for line in result["threshold_check"]["violations"]))


if __name__ == "__main__":
    unittest.main()
