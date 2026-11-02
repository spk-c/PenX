"""PX-003: Nmap CPE discovery must not accept ports rejected by Nmap inventory.

All XML is hand-authored, synthetic and parsed offline; there is no scanner,
DNS lookup, remote security provider or external-target interaction.
"""
from __future__ import annotations

from contextlib import ExitStack
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from penx_app.analysis.structured_scan_evidence import nmap_records
from penx_app.application.headless_scan import scan_report
from penx_app.application.scan_profiles import build_custom_plan
from penx_app.domain.scan_models import ScanResult, ScannerResult
from penx_app.intelligence.cve_observations import parse_nmap_services
from penx_app.reporting.machine_reports import sarif_from_report

CORPUS = Path(__file__).parent / "fixtures/scanner_corpus/nmap_xml_ports_v1.json"


class NmapXmlPortCorpusTests(unittest.TestCase):
    def setUp(self):
        self.corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.guards = [
            self.stack.enter_context(patch(name, side_effect=AssertionError("Offline Nmap corpus I/O")))
            for name in ("socket.socket.connect", "socket.getaddrinfo",
                         "requests.Session.request", "subprocess.Popen")
        ]

    def tearDown(self):
        for guard in self.guards:
            guard.assert_not_called()

    def test_version_and_fixture_identity(self):
        self.assertEqual(self.corpus["schema"], "penx-nmap-xml-corpus-v1")
        self.assertEqual(self.corpus["provenance"]["kind"], "hand-authored-synthetic")
        ids = [c["id"] for c in self.corpus["cases"]]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertGreaterEqual(len(ids), 12)
        self.assertTrue(all("<nmaprun " in c["xml"] for c in self.corpus["cases"]))

    def test_cve_product_ports_match_validated_inventory_ports(self):
        for case in self.corpus["cases"]:
            with self.subTest(case=case["id"]):
                raw = "[NMAP STRUCTURED XML]\n" + case["xml"]
                products = parse_nmap_services(raw)
                inventory = nmap_records(raw)
                self.assertEqual([product.port for product in products], case["products"])
                self.assertEqual(
                    [f"{record['port']}/{record['protocol']}" for record in inventory],
                    case["inventory"],
                )
                self.assertTrue(all(product.version == "9.2" for product in products))
                self.assertTrue(all(product.cpe.startswith("cpe:2.3:a:") for product in products))

    def test_no_cve_claim_from_nmap_xml_without_verified_finding(self):
        plan = build_custom_plan("example.test", ("1",), active_consent=False)
        for case in self.corpus["cases"]:
            with self.subTest(case=case["id"]):
                raw = "[NMAP STRUCTURED XML]\n" + case["xml"]
                # A parsed CPE is *inventory* only; it must not by itself
                # become a confirmed vulnerability in any report format.
                result = ScanResult((ScannerResult("nmap", raw, "COMPLETE",
                                                   bool(case["inventory"])),))
                report = scan_report(plan, result)
                sarif = sarif_from_report(report)
                self.assertEqual(report["schema"], "penx-scan-v1")
                self.assertEqual(report["findings"], [])
                self.assertEqual(sarif["runs"][0]["results"], [])
                self.assertEqual(report["adapters"][0]["evidence"], bool(case["inventory"]))


if __name__ == "__main__":
    unittest.main()
