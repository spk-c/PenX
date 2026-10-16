"""Scanner runtime telemetry is trusted, bounded and not fabricated for legacy data."""
import math
import sys
import unittest

from penx_app.application.scanner_execution import run_selected_structured
from penx_app.domain.scan_models import ScanRequest, ScannerOutput, ScannerResult, ScanResult
from penx_app.scanners.process_runner import run_tool
from penx_app.scanners.scan_results import format_recon_for_llm


class ScannerTelemetryTests(unittest.TestCase):
    def test_process_exit_code_survives_typed_adapter_and_view(self):
        process = run_tool([sys.executable, "-c", "print('fixture')"], timeout=5)
        self.assertEqual(process.exit_code, 0)
        result = run_selected_structured(
            ScanRequest("example.test", ("1",)),
            menu={"1": ("Nmap", lambda target: process)},
        )
        self.assertEqual(result.results[0].exit_code, 0)
        self.assertGreaterEqual(result.results[0].duration_seconds, 0)
        self.assertEqual(format_recon_for_llm(result).result.results[0].exit_code, 0)

    def test_adapter_exception_reports_diagnostic_without_forged_status(self):
        def fail(target):
            raise RuntimeError("synthetic failure")
        result = run_selected_structured(
            ScanRequest("example.test", ("1",)),
            menu={"1": ("Nmap", fail)},
        )
        finding = result.results[0]
        self.assertEqual(finding.status, "FAILED")
        self.assertFalse(finding.evidence)
        self.assertIn("synthetic failure", finding.diagnostics)
        self.assertGreaterEqual(finding.duration_seconds, 0)

    def test_stored_v1_metadata_does_not_claim_missing_legacy_telemetry(self):
        source = ScanResult((
            ScannerResult("nmap", "raw", "COMPLETE", True,
                          "Nmap", 1.5, 0, "adapter message"),
        ))
        stored = ScanResult.from_metadata(source.metadata())
        self.assertIsNone(stored.results[0].duration_seconds)
        self.assertIsNone(stored.results[0].exit_code)
        self.assertEqual(stored.results[0].diagnostics, "")

    def test_invalid_telemetry_is_rejected(self):
        for value in (-0.1, float("nan"), float("inf"), True):
            with self.subTest(value=value), self.assertRaises(ValueError):
                ScannerResult("nmap", "text", "COMPLETE", True,
                              duration_seconds=value)
        with self.assertRaises(ValueError):
            ScannerOutput("text", exit_code="error")
        with self.assertRaises(ValueError):
            ScannerResult("nmap", "text", "COMPLETE", True,
                          diagnostics="X" * 2001)


if __name__ == "__main__":
    unittest.main()
