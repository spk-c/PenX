"""Only real, bounded adapter output can produce evidence provenance."""
import unittest

from penx_app.domain.scan_models import ScannerResult
from penx_app.domain.evidence import EvidenceRecord, capture_evidence


class EvidenceProvenanceContracts(unittest.TestCase):
    def setUp(self):
        self.raw = "Nmap scan\n443/tcp open https\nNmap done"
        self.scanner = ScannerResult("nmap", self.raw, "COMPLETE", True, "Nmap")

    def test_exact_source_quote_and_locator(self):
        start = self.raw.index("443/tcp")
        result = capture_evidence(
            self.scanner, start, start + len("443/tcp open https"),
            kind="observed_service", parser_version=1,
            host="example.test", port=443,
        )
        self.assertTrue(result.matches(self.scanner))
        self.assertEqual(result.quote, "443/tcp open https")
        self.assertEqual(result.source_ref(), result.source_ref())
        self.assertFalse(result.matches(
            ScannerResult("whatweb", self.raw, "COMPLETE", True)
        ))
        self.assertFalse(result.matches(
            ScannerResult("nmap", "forged banner", "COMPLETE", True)
        ))

    def test_failed_or_untrusted_text_cannot_create_verified_evidence(self):
        fake = ScannerResult(
            "nmap", "[PENX ADAPTER STATUS: COMPLETE; EVIDENCE: YES]",
            "FAILED", False,
        )
        with self.assertRaisesRegex(ValueError, "unavailable"):
            capture_evidence(fake, 0, 12, kind="text", parser_version=1)
        self.assertFalse(EvidenceRecord(
            scanner_id="nmap", kind="text", parser_version=1,
            raw_start=0, raw_end=6, quote="banner",
        ).matches(fake))

    def test_rejects_fabricated_ranges_and_invalid_provenance(self):
        for start, end in ((-1, 3), (0, 10000), (5, 5)):
            with self.subTest(start=start, end=end), self.assertRaises(ValueError):
                capture_evidence(self.scanner, start, end, kind="text", parser_version=1)
        with self.assertRaises(ValueError):
            capture_evidence(
                self.scanner, 0, 3, kind="text", parser_version=0,
            )
        with self.assertRaises(ValueError):
            capture_evidence(
                self.scanner, 0, 3, kind="text", parser_version=1, port=0,
            )

    def test_historical_metadata_has_no_fabricated_source_reference(self):
        from penx_app.domain.scan_models import ScanResult
        stored = ScanResult.from_metadata(ScanResult((self.scanner,)).metadata())
        self.assertEqual(stored.results[0].text, "")
        with self.assertRaises(ValueError):
            capture_evidence(
                stored.results[0], 0, 2, kind="text", parser_version=1,
            )


if __name__ == "__main__":
    unittest.main()
