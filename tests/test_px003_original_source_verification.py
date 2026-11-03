"""PX-003 full-source provenance contracts; disposable files only."""
from dataclasses import replace
from contextlib import redirect_stdout
from io import StringIO
import json
from pathlib import Path
import tempfile
import unittest

from penx_app.domain.evidence import capture_evidence, revalidate_persisted_evidence
from penx_app.application.evidence_verification import main as evidence_cli, verify_metadata_file
from penx_app.domain.scan_models import ScanResult, ScannerResult
from penx_app.storage.raw_artifacts import retain_artifacts, revalidate_retained_evidence


def scanner(text="443/tcp open https\nA synthetic untrusted trailer\n"):
    base=ScannerResult("nmap", text, "COMPLETE", True, "Nmap")
    anchor=capture_evidence(base, 0, len("443/tcp open https"),
                            kind="observed_service", parser_version=1)
    return replace(base,evidence_records=(anchor,))


class OriginalSourceVerificationTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root=Path(temp.name)

    def retained(self):
        saved=retain_artifacts(ScanResult((scanner(),)), self.root)
        self.saved_metadata = saved.metadata()
        return ScanResult.from_metadata(self.saved_metadata)

    def test_valid_full_source_revalidation_passes(self):
        stored=self.retained()
        original=scanner()
        self.assertEqual(len(revalidate_persisted_evidence(stored, (original,))),1)
        self.assertEqual(revalidate_retained_evidence(stored, self.root),
                         original.evidence_records)

    def test_same_quote_different_trailer_must_not_verify_original_hash(self):
        stored=self.retained()
        forged=scanner("443/tcp open https\nDifferent substituted trailer\n")
        self.assertEqual(forged.evidence_records, stored.results[0].evidence_records)
        with self.assertRaisesRegex(ValueError, "source"):
            revalidate_persisted_evidence(stored, (forged,))

    def test_corrupted_raw_file_fails_closed(self):
        stored=self.retained()
        file=self.root/stored.results[0].raw_artifact.filename
        file.write_text("443/tcp open https\nTampered",encoding="utf-8")
        with self.assertRaises(ValueError):
            revalidate_retained_evidence(stored,self.root)

    def test_missing_artifact_fails_closed(self):
        stored=self.retained()
        (self.root/stored.results[0].raw_artifact.filename).unlink()
        with self.assertRaises((OSError, ValueError)):
            revalidate_retained_evidence(stored,self.root)

    def test_historical_anchors_without_original_bytes_not_certified(self):
        historical=ScanResult.from_metadata(ScanResult((scanner(),)).metadata())
        self.assertIsNone(historical.results[0].raw_artifact)
        with self.assertRaises(ValueError):
            revalidate_retained_evidence(historical,self.root)

    def test_no_evidence_does_not_get_false_verified_result(self):
        clean=ScanResult((ScannerResult("nmap","","FAILED",False,"Nmap"),))
        with self.assertRaises(ValueError):
            revalidate_retained_evidence(clean,self.root)

    def test_cli_verifies_stored_metadata_without_disclosing_raw_text(self):
        stored=self.retained()
        manifest=self.root/"metadata.json"
        manifest.write_text(self.saved_metadata,encoding="utf-8")
        report=verify_metadata_file(manifest,self.root)
        self.assertEqual(report["status"],"verified-retained-integrity")
        self.assertEqual(report["raw_sources_verified"],1)
        self.assertEqual(report["anchors_verified"],1)
        stream=StringIO()
        with redirect_stdout(stream):
            code=evidence_cli(["--metadata",str(manifest),
                               "--artifacts",str(self.root)])
        self.assertEqual(code,0)
        parsed=json.loads(stream.getvalue())
        self.assertEqual(parsed["raw_sources_verified"],1)
        self.assertNotIn("443/tcp",stream.getvalue())
        self.assertNotIn("A synthetic untrusted trailer",stream.getvalue())

    def test_cli_tampered_file_fails_closed_without_echoing_source(self):
        stored=self.retained()
        manifest=self.root/"metadata.json"
        manifest.write_text(self.saved_metadata,encoding="utf-8")
        file=self.root/stored.results[0].raw_artifact.filename
        file.write_text("443/tcp open https\\nsecret-should-not-appear\\n",encoding="utf-8")
        stream=StringIO()
        with redirect_stdout(stream):
            code=evidence_cli(["--metadata",str(manifest),
                               "--artifacts",str(self.root)])
        self.assertEqual(code,2)
        self.assertEqual(json.loads(stream.getvalue())["status"],"unverified")
        self.assertNotIn("secret-should-not-appear",stream.getvalue())

    def test_cli_rejects_oversized_metadata_without_reading_whole_file(self):
        manifest=self.root/"huge.json"
        manifest.write_bytes(b"A"*100001)
        with self.assertRaisesRegex(ValueError,"size"):
            verify_metadata_file(manifest,self.root)

    def test_cli_rejects_legacy_metadata_with_no_retained_source(self):
        manifest=self.root/"legacy.json"
        manifest.write_text(ScanResult((scanner(),)).metadata(),encoding="utf-8")
        stream=StringIO()
        with redirect_stdout(stream):
            code=evidence_cli(["--metadata",str(manifest),
                               "--artifacts",str(self.root)])
        self.assertEqual(code,2)
        self.assertEqual(json.loads(stream.getvalue())["status"],"unverified")

    def test_bootstrap_routes_offline_verification(self):
        from unittest.mock import patch
        from penx_app.bootstrap import main as bootstrap
        with patch("sys.argv",["penx","evidence","verify","--metadata","m",
                               "--artifacts","d"]), \
             patch("penx_app.application.evidence_verification.main",
                   return_value=0) as entry:
            self.assertEqual(bootstrap(),0)
        entry.assert_called_once_with(["--metadata","m","--artifacts","d"])

    def test_metadata_roundtrip_source_hash_matches_file(self):
        stored=self.retained()
        payload=json.loads(self.saved_metadata)
        self.assertEqual(payload["version"],3)
        reference=payload["adapters"][0]["raw_artifact"]
        self.assertEqual(reference["size_bytes"],(self.root/reference["filename"]).stat().st_size)


if __name__=="__main__":
    unittest.main()
