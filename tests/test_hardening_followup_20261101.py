"""Regression checks for bounded CVE results and scanner events."""
from __future__ import annotations
import unittest
from unittest.mock import Mock
from penx_app.intelligence import cve_engine as cve
from penx_app.intelligence.cve_observations import parse_explicit_packages
from penx_app.application.scan_planner import _terminal_event
from penx_app.domain.scan_models import ScannerOutput
from penx_app.domain.scan_diagnostics import ScannerRunEvent

PKG = parse_explicit_packages("pkg:pypi/requests@2.31.0")[0]

def page(ident: str, token: str = "") -> Mock:
    r = Mock()
    r.json.return_value = {"vulns": [{"id": ident}], "next_page_token": token}
    return r

class HardeningTests(unittest.TestCase):
    def test_osv_page_cap_has_warning(self):
        client = Mock(side_effect=[page("OSV-ONE", "next"), page("OSV-TWO", "more")])
        rows, note = cve.osv_candidates(PKG, limit=10, http_post=client)
        self.assertEqual(len(rows), 2)
        self.assertIn("page cap reached", note)

    def test_osv_final_page_no_warning(self):
        client = Mock(side_effect=[page("OSV-ONE", "next"), page("OSV-TWO")])
        rows, note = cve.osv_candidates(PKG, limit=10, http_post=client)
        self.assertEqual((len(rows), note), (2, ""))

    def test_osv_limit_is_visible(self):
        rows, note = cve.osv_candidates(PKG, limit=1, http_post=lambda *a, **k: page("OSV-ONE"))
        self.assertEqual(len(rows), 1)
        self.assertIn("display limit reached", note)

    def test_partial_is_not_completed(self):
        partial = ScannerOutput("partial", status="PARTIAL", diagnostics="incomplete")
        self.assertEqual(_terminal_event(partial), "partial")
        self.assertEqual(ScannerRunEvent("nmap", "partial", None, None, "").event, "partial")

if __name__ == "__main__":
    unittest.main(verbosity=2)
