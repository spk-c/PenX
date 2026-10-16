"""Regression tests for lossless scanner telemetry across the CLI boundary.

All scanner calls are synthetic: no real target, subprocess or network.
"""
from __future__ import annotations

import unittest
from unittest.mock import Mock, patch

from penx_app.application.scanner_execution import run_selected_structured
from penx_app.cli.scanner_menu import interactive_tool_run
from penx_app.domain.scan_models import ScanRequest, ScanResult, ScannerOutput, ScannerResult
from penx_app.scanners.scan_results import format_recon_for_llm
from penx_app.scanners.tools import run_nmap


class ScannerTelemetryBoundaryTests(unittest.TestCase):
    def test_scanner_picker_preserves_duration_exit_and_diagnostics(self):
        original = ScanResult((
            ScannerResult("nmap", "80/tcp open http", "COMPLETE", True,
                          "Nmap", 1.25, 0, "bounded status"),
        ))
        with patch("penx_app.cli.cli_navigation.navigation_input", return_value="1"), \
             patch("penx_app.application.scanner_execution.run_selected_structured",
                   return_value=original) as scanner:
            result = interactive_tool_run(
                "fixture.example.test", menu={"1": ("Nmap", Mock())},
                formatter=format_recon_for_llm,
            )
        scanner.assert_called_once()
        outcome = result.result.results[0]
        self.assertEqual(outcome.duration_seconds, 1.25)
        self.assertEqual(outcome.exit_code, 0)
        self.assertEqual(outcome.diagnostics, "bounded status")
        self.assertEqual(outcome.scanner_id, "nmap")
        self.assertEqual(outcome.status, "COMPLETE")

    def test_http_508_skip_keeps_registered_adapter_identity(self):
        nuclei = Mock(side_effect=AssertionError("Nuclei should not run"))
        result = run_selected_structured(
            ScanRequest("fixture.example.test", ("4", "7"), active_consent=True),
            menu={
                "4": ("HTTP Headers", lambda _: ScannerOutput(
                    "HTTP 508 Resource Limit Is Reached", status="COMPLETE")),
                "7": ("Nuclei", nuclei),
            },
        )
        nuclei.assert_not_called()
        skipped = result.results[1]
        self.assertEqual(skipped.scanner_id, "nuclei")
        self.assertEqual(skipped.status, "PARTIAL")
        self.assertFalse(skipped.evidence)
        self.assertIn("HTTP 508", skipped.diagnostics)
        self.assertEqual(skipped.evidence_records, ())

    def test_nmap_wrapper_keeps_native_process_exit_telemetry(self):
        native = ScannerOutput("synthetic nmap output", status="FAILED",
                               evidence=False, exit_code=3,
                               diagnostics="synthetic process error")
        with patch("penx_app.scanners.tools._host", return_value="fixture.example.test"), \
             patch("penx_app.scanners.tools._executable", return_value="nmap"), \
             patch("penx_app.scanners.tools.run_tool", return_value=native):
            result = run_nmap("fixture.example.test")
        self.assertEqual(result.exit_code, 3)
        self.assertEqual(result.diagnostics, "synthetic process error")
        self.assertEqual(result.status, "FAILED")
        self.assertFalse(result.evidence)


if __name__ == "__main__":
    unittest.main(verbosity=2)
