"""PX-203 explainable evidence traceability parity and fail-closed tests.

All sources and reports are synthetic, in-memory, offline. Tier 2 reflects
typed completion of one matched saved section, NOT vulnerability verification.
"""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from penx_app.domain.scan_models import ScanResult, ScannerResult
from penx_app.reporting.evidence_quality import evidence_traceability
from penx_app.reporting.export import export_html, export_pdf
from penx_app.reporting.machine_reports import (
    report_payload, sarif_from_report, sarif_payload,
)
from penx_app.reporting.report_design import _report


class EvidenceTraceabilityContracts(unittest.TestCase):
    def setUp(self):
        self.nmap = "443/tcp open https fixture-tls"
        self.httpx = "HTTP/1.1 200 OK"
        self.raw = (
            "[ NMAP OUTPUT ]\n" + self.nmap + "\n"
            "[ HTTPX OUTPUT ]\n" + self.httpx + "\n"
        )
        self.rows = [
            (1, 41, "Observed Nmap", "medium", "confirmed", "443", "https",
             "Saved scanner observation\nEvidence: " + self.nmap),
            (2, 41, "AI invented finding", "critical", "confirmed", "80",
             "http", "No verified observation"),
            (3, 41, "Partial Httpx", "low", "possible", "443", "https",
             "Evidence: " + self.httpx),
        ]
        self.data = {
            "history": (41, "fixture.example.test", "2026-11-04", "active"),
            "summary": (9, 41, self.raw, "Synthetic model narrative",
                        "MEDIUM", "fixture", "2026-11-04"),
            "vulns": self.rows,
            "fixes": [],
            "corrections": [],
            "exploits": [],
            "scan_result": ScanResult((
                ScannerResult("nmap", self.nmap, "COMPLETE", True, "Nmap"),
                ScannerResult("httpx", self.httpx, "PARTIAL", True, "Httpx"),
            )),
        }

    def qualities(self):
        return {
            item["id"]: item["evidence_quality"]
            for item in report_payload(self.data)["findings"]
        }

    def test_tiers_reflect_traceability_not_model_confidence(self):
        info = self.qualities()
        self.assertEqual(
            {key: value["traceability_tier"] for key, value in info.items()},
            {1: 2, 2: 0, 3: 1},
        )
        self.assertEqual(info[1]["dimensions"]["source_identity"],
                         "unique-saved-section")
        self.assertEqual(info[1]["dimensions"]["coverage"], "COMPLETE")
        self.assertEqual(info[3]["dimensions"]["coverage"], "PARTIAL")
        self.assertEqual(info[2]["dimensions"]["quote"], "not-established")
        self.assertEqual(info[1]["dimensions"]["freshness"],
                         "recorded-date-only-not-age-verified")
        for result in info.values():
            self.assertFalse(result["original_source_revalidated"])
            self.assertFalse(result["independent_corroboration_verified"])
            self.assertFalse(result["vulnerability_verified"])
            self.assertFalse(result["exploitability_verified"])
            self.assertTrue(result["operator_review_required"])
        exported = report_payload(self.data)
        self.assertEqual(exported["findings"][1]["confidence"], "possible")

    def test_missing_adapter_metadata_does_not_claim_complete(self):
        self.data.pop("scan_result")
        info = self.qualities()
        self.assertEqual(info[1]["traceability_tier"], 1)
        self.assertEqual(info[1]["dimensions"]["coverage"], "UNKNOWN")
        self.assertEqual(info[1]["dimensions"]["source_identity"],
                         "unique-saved-section")
        self.assertEqual(info[3]["traceability_tier"], 1)
        self.assertFalse(info[1]["original_source_revalidated"])

    def test_duplicate_sections_do_not_establish_source_identity(self):
        self.data["summary"] = (
            9, 41, self.raw + "[ NMAP OUTPUT ]\n" + self.nmap,
            "Synthetic model narrative", "MEDIUM", "fixture", "2026-11-04")
        info = self.qualities()
        self.assertEqual(info[1]["traceability_tier"], 1)
        self.assertEqual(info[1]["dimensions"]["source_identity"], "unattributed")
        self.assertEqual(info[1]["dimensions"]["coverage"], "UNKNOWN")

    def test_complete_metadata_but_missing_quote_stays_unattributed(self):
        row = self.rows[0]
        self.data["vulns"][0] = (*row[:-1], "Evidence: no-such-observation")
        quality = self.qualities()[1]
        self.assertEqual(quality["traceability_tier"], 0)
        self.assertEqual(quality["dimensions"]["source_identity"], "unattributed")
        self.assertEqual(quality["dimensions"]["coverage"], "UNKNOWN")

    def test_raw_reference_is_not_revalidated_source_proof(self):
        trace = {
            "scanner": "NMAP", "scanner_status": "COMPLETE",
            "recorded_at": "2026-11-04",
            "artifact_status": "stored-reference-not-revalidated",
            "raw_artifact": {"sha256": "0" * 64},
        }
        result = evidence_traceability(trace, quote_matched=True)
        self.assertEqual(result["traceability_tier"], 2)
        self.assertEqual(result["dimensions"]["raw_artifact"],
                         "retained-reference-unverified")
        self.assertFalse(result["original_source_revalidated"])
        self.assertFalse(result["vulnerability_verified"])

    def test_sarif_preserves_json_vector_for_each_saved_finding(self):
        json_items = report_payload(self.data)["findings"]
        sarif_items = sarif_payload(self.data)["runs"][0]["results"]
        self.assertEqual(
            [item["properties"]["penxFindingId"] for item in sarif_items],
            [item["id"] for item in json_items],
        )
        for json_item, sarif_item in zip(json_items, sarif_items, strict=True):
            self.assertEqual(sarif_item["properties"]["evidenceQuality"],
                             json_item["evidence_quality"])
        self.assertNotIn("fixture-tls", json.dumps(
            [item["properties"]["evidenceQuality"] for item in sarif_items]))

    def test_headless_sarif_without_vector_defaults_to_unverified(self):
        report = report_payload(self.data)
        for entry in report["findings"]:
            entry.pop("evidence_quality")
        sarif = sarif_from_report(report)
        for result in sarif["runs"][0]["results"]:
            quality = result["properties"]["evidenceQuality"]
            self.assertLessEqual(quality["traceability_tier"], 1)
            self.assertFalse(quality["original_source_revalidated"])

    def test_html_and_pdf_project_the_same_tiers_without_new_scans(self):
        report = report_payload(self.data)
        levels = {item["id"]: item["evidence_quality"]
                  for item in report["findings"]}
        projection = _report(self.data)
        self.assertEqual(projection["evidence_quality_by_id"], levels)
        with tempfile.TemporaryDirectory(prefix="px203-parity-") as directory:
            with patch("socket.create_connection",
                       side_effect=AssertionError("network prohibited")), \
                 patch("subprocess.run",
                       side_effect=AssertionError("scanner execution prohibited")):
                html_file = Path(export_html(self.data, directory))
                pdf_file = Path(export_pdf(self.data, directory))
            html = html_file.read_text(encoding="utf-8")
            self.assertIn("Evidence traceability: Tier 2/2", html)
            self.assertIn("Evidence traceability: Tier 1/2", html)
            self.assertIn("Evidence traceability: Tier 0/2", html)
            self.assertIn("source bytes not independently revalidated", html)
            self.assertTrue(pdf_file.read_bytes().startswith(b"%PDF"))
            self.assertGreater(pdf_file.stat().st_size, 750)

    def test_null_unknown_fields_fail_conservatively(self):
        result = evidence_traceability(
            {"scanner": None, "scanner_status": "COMPLETE",
             "recorded_at": None, "artifact_status": "stored-reference-not-revalidated"},
            quote_matched=False,
        )
        self.assertEqual(result["traceability_tier"], 0)
        self.assertEqual(result["dimensions"]["coverage"], "UNKNOWN")
        self.assertEqual(result["dimensions"]["freshness"], "unknown")
        self.assertEqual(result["dimensions"]["raw_artifact"],
                         "not-independently-verified")

    def test_inconsistent_status_does_not_upgrade_inferred_quote(self):
        for status in ("FAILED", "PARTIAL", "UNKNOWN", None):
            with self.subTest(status=status):
                result = evidence_traceability({
                    "scanner": "NMAP", "scanner_status": status,
                    "recorded_at": "2026-11-04",
                }, quote_matched=True)
                self.assertEqual(result["traceability_tier"], 1)


if __name__ == "__main__":
    unittest.main()
