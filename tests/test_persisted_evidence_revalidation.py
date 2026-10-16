"""Revalidate persisted adapter anchors only against independent source text."""
from __future__ import annotations

import unittest

from penx_app.domain.evidence import (
    capture_evidence, revalidate_persisted_evidence,
)
from penx_app.domain.scan_models import ScanResult, ScannerResult


class PersistedEvidenceRevalidationTests(unittest.TestCase):
    def setUp(self):
        self.raw = "Nmap done\n80/tcp open http\n"
        self.original = ScannerResult("nmap", self.raw, "COMPLETE", True, "Nmap")
        self.anchor = capture_evidence(
            self.original, 0, len(self.raw),
            kind="adapter_output", parser_version=1,
        )
        marked = ScannerResult(
            "nmap", self.raw, "COMPLETE", True, "Nmap",
            evidence_records=(self.anchor,),
        )
        self.stored = ScanResult.from_metadata(ScanResult((marked,)).metadata())
        self.assertEqual(self.stored.results[0].text, "")

    def test_original_source_validates_restored_evidence(self):
        self.assertEqual(
            revalidate_persisted_evidence(self.stored, [self.original]),
            (self.anchor,),
        )
        # The stored result alone cannot stand in for a source.
        with self.assertRaisesRegex(ValueError, "does not match"):
            revalidate_persisted_evidence(self.stored, self.stored.results)

    def test_mutated_output_fails_closed(self):
        altered = ScannerResult(
            "nmap", "Nmap done\n80/tcp closed http\n", "COMPLETE", True, "Nmap"
        )
        with self.assertRaisesRegex(ValueError, "does not match"):
            revalidate_persisted_evidence(self.stored, [altered])

    def test_missing_source_and_different_adapter_fail_closed(self):
        for originals in (
            [],
            [ScannerResult("whatweb", self.raw, "COMPLETE", True)],
        ):
            with self.subTest(originals=originals), self.assertRaisesRegex(
                ValueError, "missing"
            ):
                revalidate_persisted_evidence(self.stored, originals)

    def test_failed_or_untrusted_source_cannot_revalidate(self):
        for source in (
            ScannerResult("nmap", self.raw, "FAILED", False),
            ScannerResult("nmap", self.raw, "PARTIAL", False),
        ):
            with self.subTest(status=source.status), self.assertRaisesRegex(
                ValueError, "does not match"
            ):
                revalidate_persisted_evidence(self.stored, [source])

    def test_duplicate_source_ids_rejected_before_matching(self):
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            revalidate_persisted_evidence(
                self.stored, [self.original, self.original]
            )

    def test_legacy_metadata_without_anchors_requires_no_raw_source(self):
        original = ScannerResult("nmap", self.raw, "COMPLETE", True, "Nmap")
        old = ScanResult.from_metadata(ScanResult((original,)).metadata())
        self.assertEqual(revalidate_persisted_evidence(old, []), ())


if __name__ == "__main__":
    unittest.main(verbosity=2)
