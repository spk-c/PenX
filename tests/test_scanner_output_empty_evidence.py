"""Regression tests for the trusted string-compatible scanner output boundary."""
from __future__ import annotations

import unittest

from penx_app.domain.scan_models import ScannerOutput
from penx_app.scanners.scan_results import format_recon_for_llm, recon_has_evidence


class ScannerOutputEvidenceIntegrityTests(unittest.TestCase):
    def test_empty_completed_output_cannot_claim_verified_evidence(self):
        for value in ("", "  ", "\n\t"):
            with self.subTest(value=value):
                adapter = ScannerOutput(value, status="COMPLETE", evidence=True)
                self.assertEqual(adapter.status, "COMPLETE")
                self.assertFalse(adapter.evidence)
                formatted = format_recon_for_llm({"Nmap": adapter})
                self.assertFalse(formatted.result.has_evidence)
                self.assertFalse(recon_has_evidence(formatted))
                self.assertIn("EVIDENCE: NO", formatted)

    def test_arbitrary_nontext_outputs_cannot_be_recast_as_scanner_evidence(self):
        for source in (None, True, 42, ["a"], {"ok": True}, object()):
            with self.subTest(source=type(source).__name__):
                with self.assertRaises(TypeError):
                    ScannerOutput(source, status="COMPLETE", evidence=True)

    def test_partial_text_is_valid_only_when_adapter_explicitly_marks_evidence(self):
        observed = ScannerOutput("A: 192.0.2.1", status="PARTIAL", evidence=True)
        self.assertTrue(observed.evidence)
        self.assertTrue(recon_has_evidence(format_recon_for_llm({"DNS": observed})))
        no_evidence = ScannerOutput("A: 192.0.2.1", status="PARTIAL", evidence=False)
        self.assertFalse(no_evidence.evidence)

    def test_nonempty_complete_and_failed_outputs_keep_existing_semantics(self):
        self.assertTrue(ScannerOutput("80/tcp open http").evidence)
        self.assertFalse(ScannerOutput("80/tcp open http", status="FAILED").evidence)


if __name__ == "__main__":
    unittest.main()
