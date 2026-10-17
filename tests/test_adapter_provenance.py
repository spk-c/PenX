"""Adapter execution attaches bounded EvidenceRecord provenance per scanner."""
import unittest

from penx_app.application.scanner_execution import run_selected_structured
from penx_app.domain.evidence import EvidenceRecord, capture_evidence
from penx_app.domain.scan_models import (
    ReconText, ScanRequest, ScanResult, ScannerOutput, ScannerResult,
)
from penx_app.scanners.scan_results import format_recon_for_llm

PARSER_VERSION = 1


class AdapterProvenanceContracts(unittest.TestCase):
    # Helper names avoid TestCase API names (``run`` in particular), which
    # TestSuite invokes on the test object and would otherwise swallow the
    # real test run, reporting "Ran 0 tests" while silently passing.
    def make_menu(self, body):
        return {
            "1": ("Nmap", lambda target: ScannerOutput(body, status="COMPLETE")),
            "2": ("Whois", lambda target: ScannerOutput(
                "[!] WHOIS: registry lookup failed", status="FAILED", evidence=False)),
        }

    def run_scan(self, body):
        return run_selected_structured(
            ScanRequest("fixture.example.test", ("1", "2")), menu=self.make_menu(body))

    def test_evidence_adapter_carries_one_verifiable_record(self):
        body = "Nmap done\n443/tcp open https\n"
        result = self.run_scan(body)
        ok, failed = result.results
        self.assertEqual(len(ok.evidence_records), 1)
        record = ok.evidence_records[0]
        self.assertIsInstance(record, EvidenceRecord)
        self.assertEqual(record.scanner_id, "nmap")
        self.assertEqual(record.kind, "adapter_output")
        self.assertEqual(record.parser_version, PARSER_VERSION)
        self.assertTrue(record.matches(ok))
        self.assertEqual(record.quote, body)
        self.assertEqual(record.source_ref(), record.source_ref())
        self.assertEqual(failed.evidence_records, ())
        # The aggregate spans adapters in result order.
        self.assertEqual(result.evidence_records(), (record,))

    def test_provenance_window_is_bounded_to_two_thousand_chars(self):
        body = "x" * 5000
        result = self.run_scan(body)
        record = result.results[0].evidence_records[0]
        self.assertEqual(record.raw_start, 0)
        self.assertEqual(record.raw_end, 2000)
        self.assertEqual(record.quote, body[:2000])

    def test_failed_or_blank_adapters_carry_no_records(self):
        result = self.run_scan("  \n")
        ok, failed = result.results
        # Blank adapter responses cannot be trusted evidence, even when
        # their legacy runner reported a COMPLETE process exit.
        self.assertFalse(ok.evidence)
        self.assertEqual(ok.evidence_records, ())
        self.assertEqual(failed.evidence_records, ())
        self.assertEqual(result.evidence_records(), ())

    def test_records_survive_the_formatting_boundary(self):
        result = self.run_scan("Nmap done\n80/tcp open http\n")
        report = format_recon_for_llm(result)
        self.assertIsInstance(report, ReconText)
        records = report.result.evidence_records()
        self.assertEqual(len(records), 1)
        self.assertTrue(records[0].matches(report.result.results[0]))
        self.assertEqual(records[0].source_ref(),
                         result.evidence_records()[0].source_ref())

    def test_dict_boundary_carries_records_into_recon(self):
        output = ScannerOutput("whois text", status="COMPLETE", scanner_id="whois")
        report = format_recon_for_llm({"Whois": output})
        self.assertEqual(report.result.evidence_records(), ())
        # A record attached to the adapter output is preserved verbatim.
        source = ScannerResult("whois", "whois text", "COMPLETE", True)
        record = capture_evidence(
            source, 0, len("whois text"),
            kind="adapter_output", parser_version=PARSER_VERSION,
        )
        proven = ScannerOutput(
            "whois text", status="COMPLETE", scanner_id="whois",
            evidence_records=(record,))
        report = format_recon_for_llm({"Whois": proven})
        self.assertEqual(report.result.evidence_records(), (record,))

    def test_metadata_round_trip_preserves_bounded_adapter_records(self):
        result = self.run_scan("Nmap done\n")
        metadata = result.metadata()
        self.assertIn('"version": 2', metadata)
        stored = ScanResult.from_metadata(metadata)
        self.assertEqual(stored.evidence_records(), result.evidence_records())
        self.assertEqual(stored.results[0].text, '')
        # Source revalidation after reload requires the original adapter text.
        self.assertFalse(stored.evidence_records()[0].matches(stored.results[0]))

    def test_legacy_v1_metadata_without_records_stays_readable(self):
        record = ScannerResult("whois", "", "COMPLETE", False)
        encoded = ScanResult((record,)).metadata()
        self.assertIn('"version": 1', encoded)
        self.assertEqual(ScanResult.from_metadata(encoded).evidence_records(), ())

    def test_tampered_metadata_is_rejected(self):
        import json
        metadata = json.loads(self.run_scan("Nmap done\n").metadata())
        record = metadata['adapters'][0]['records'][0]
        record['scanner_id'] = 'injected'
        with self.assertRaisesRegex(ValueError, 'contradicts scanner'):
            ScanResult.from_metadata(json.dumps(metadata))
        record['scanner_id'] = metadata['adapters'][0]['id']
        record['raw_end'] = 99999
        with self.assertRaisesRegex(ValueError, 'Invalid evidence'):
            ScanResult.from_metadata(json.dumps(metadata))
        # In-bounds but inconsistent offsets must not be accepted either.
        record['raw_end'] = record['raw_start'] + len(record['quote']) + 1
        with self.assertRaisesRegex(ValueError, 'Invalid evidence'):
            ScanResult.from_metadata(json.dumps(metadata))

    def test_serialization_rejects_record_from_different_output(self):
        source = ScannerResult("nmap", "80/tcp open", "COMPLETE", True)
        anchor = capture_evidence(source, 0, len(source.text),
                                  kind="adapter_output", parser_version=1)
        altered = ScannerResult("nmap", "closed", "COMPLETE", True,
                                evidence_records=(anchor,))
        with self.assertRaisesRegex(ValueError, 'does not match'):
            ScanResult((altered,)).metadata()


if __name__ == "__main__":
    unittest.main()
