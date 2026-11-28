"""Offline tests for PX-405: provider cache freshness and applicability diagnostics.

These tests verify that the CVE research report exposes source freshness,
cache TTL and per-provider availability so that "no match" can be told apart
from "provider unavailable", and that stale reference data is never presented
as a fresh source.
"""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from penx_app.intelligence import nvd_disk_cache
from penx_app.intelligence.cve_observations import parse_nmap_services
from penx_app.intelligence.cve_engine import (
    nvd_candidates, discover, format_report, _cached_nvd,
)

SAMPLE_XML = """[NMAP STRUCTURED XML]
<nmaprun scanner="nmap">
 <host>
  <ports>
   <port protocol="tcp" portid="22">
    <state state="open"/>
    <service name="ssh" product="OpenSSH" version="9.2">
      <cpe>cpe:/a:openbsd:openssh:9.2</cpe>
    </service>
   </port>
  </ports>
 </host>
</nmaprun>"""

# A package line so OSV/GitHub lookups are exercised by discover().
SAMPLE_WITH_PKG = SAMPLE_XML + "\n\npkg:pypi/requests@2.31.0\n"

CPE = "cpe:2.3:a:openbsd:openssh:9.2:*:*:*:*:*:*:*"


def record(cve="CVE-2024-9999", *, start="9.0", end="9.4"):
    matches = [{"vulnerable": True,
                "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                "versionStartIncluding": start, "versionEndExcluding": end}]
    return {"cve": {
        "id": cve, "vulnStatus": "Analyzed",
        "configurations": [{"nodes": [{"operator": "OR", "cpeMatch": matches}]}],
        "references": [],
    }}


def response(payload, status=200):
    res = Mock()
    res.status_code = status
    res.headers = {}
    res.json.return_value = payload
    res.raise_for_status.return_value = None
    return res


class FreshnessHelperTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="penx-nvd-cache-")
        self.addCleanup(self.temp.cleanup)
        self.directory = patch.object(nvd_disk_cache, "CACHE_DIR", Path(self.temp.name))
        self.directory.start()
        self.addCleanup(self.directory.stop)

    def test_freshness_returns_age_and_ttl(self):
        self.assertTrue(nvd_disk_cache.store(CPE, (record(),), now=1000.0))
        fresh = nvd_disk_cache.freshness(CPE, now=1360.0)
        self.assertIsNotNone(fresh)
        self.assertEqual(fresh["ttl_seconds"], nvd_disk_cache.TTL_SECONDS)
        self.assertAlmostEqual(fresh["age_seconds"], 360.0, places=1)

    def test_freshness_expired_returns_none(self):
        self.assertTrue(nvd_disk_cache.store(CPE, (record(),), now=1000.0))
        self.assertIsNone(nvd_disk_cache.freshness(
            CPE, now=1000.0 + nvd_disk_cache.TTL_SECONDS + 1))

    def test_freshness_missing_returns_none(self):
        self.assertIsNone(nvd_disk_cache.freshness(CPE, now=1360.0))

    def test_freshness_malformed_returns_none(self):
        path = nvd_disk_cache.cache_path(CPE)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{not json", encoding="utf-8")
        self.assertIsNone(nvd_disk_cache.freshness(CPE, now=1360.0))

    def test_freshness_disabled_returns_none(self):
        self.assertTrue(nvd_disk_cache.store(CPE, (record(),), now=1000.0))
        with patch.dict("os.environ", {"PENX_NVD_DISK_CACHE": "0"}):
            self.assertIsNone(nvd_disk_cache.freshness(CPE, now=1360.0))


class NvdCandidatesFreshnessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="penx-nvd-cache-")
        self.addCleanup(self.temp.cleanup)
        self.directory = patch.object(nvd_disk_cache, "CACHE_DIR", Path(self.temp.name))
        self.directory.start()
        self.addCleanup(self.directory.stop)
        _cached_nvd.cache_clear()
        self.addCleanup(_cached_nvd.cache_clear)

    def test_cache_fresh_reports_cache_fresh(self):
        product = parse_nmap_services(SAMPLE_XML, max_services=1)[0]
        self.assertEqual(product.cpe, CPE)
        self.assertTrue(nvd_disk_cache.store(product.cpe, (record(),)))
        candidates, warn = nvd_candidates(product)
        self.assertEqual(warn, "")
        self.assertTrue(candidates)
        for candidate in candidates:
            self.assertIn("cache fresh", candidate["source_freshness"])
            self.assertIn("86400s TTL", candidate["source_freshness"])

    def test_live_fetch_reports_live(self):
        product = parse_nmap_services(SAMPLE_XML, max_services=1)[0]
        candidates, warn = nvd_candidates(
            product,
            http_get=lambda *a, **k: response(
                {"vulnerabilities": [record()], "totalResults": 1}))
        self.assertEqual(warn, "")
        self.assertTrue(candidates)
        for candidate in candidates:
            self.assertIn("live", candidate["source_freshness"])


class DiscoverDiagnosticsTests(unittest.TestCase):
    def _run(self, nvd_lookup=None, osv_lookup=None, github_lookup=None,
             xml=SAMPLE_WITH_PKG):
        return discover(
            xml, nvd_lookup=nvd_lookup, osv_lookup=osv_lookup,
            github_lookup=github_lookup, priority=False,
        )

    def test_provider_availability_tracked_per_provider(self):
        output = self._run(
            nvd_lookup=lambda p, **kw: ([], "NVD unavailable for " + p.cpe),
            osv_lookup=lambda pkg, **kw: ([], "OSV unavailable for " + pkg.purl),
            github_lookup=lambda pkg, **kw: ([], "GitHub Advisories unavailable for " + pkg.purl),
        )
        self.assertIn("nvd", output["source_diagnostics"])
        self.assertIn("osv", output["source_diagnostics"])
        self.assertIn("github", output["source_diagnostics"])
        self.assertFalse(output["source_diagnostics"]["nvd"]["available"])
        self.assertFalse(output["source_diagnostics"]["osv"]["available"])
        self.assertFalse(output["source_diagnostics"]["github"]["available"])
        self.assertEqual(output["source_diagnostics"]["nvd"]["ttl_seconds"],
                         nvd_disk_cache.TTL_SECONDS)

    def test_available_provider_with_no_match_is_not_unavailable(self):
        output = self._run(
            nvd_lookup=lambda p, **kw: ([], ""),
            osv_lookup=lambda pkg, **kw: ([], ""),
            github_lookup=lambda pkg, **kw: ([], ""),
        )
        self.assertTrue(output["source_diagnostics"]["nvd"]["available"])
        self.assertTrue(output["source_diagnostics"]["osv"]["available"])
        self.assertTrue(output["source_diagnostics"]["github"]["available"])
        text = format_report(output)
        self.assertNotIn("unavailable", text)
        self.assertIn("No version-qualified CVE candidates", text)

    def test_all_unavailable_reports_unavailable_not_no_match(self):
        output = self._run(
            nvd_lookup=lambda p, **kw: ([], "NVD unavailable for " + p.cpe),
            osv_lookup=lambda pkg, **kw: ([], "OSV unavailable for " + pkg.purl),
            github_lookup=lambda pkg, **kw: ([], "GitHub Advisories unavailable for " + pkg.purl),
        )
        text = format_report(output)
        self.assertIn("all queried sources were unavailable", text)


class FormatReportFreshnessTests(unittest.TestCase):
    def test_renders_freshness_and_status(self):
        report = {
            "observations": ["cpe:/a:openbsd:openssh:9.2"],
            "candidates": [{
                "id": "CVE-2024-9999", "source": "NVD",
                "status": "version-match-needs-vendor-review",
                "product": "OpenSSH", "version": "9.2",
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-9999",
                "source_freshness": "NVD cache fresh (0.0s old, 86400s TTL)",
            }],
            "warnings": [],
            "source_diagnostics": {
                "nvd": {"available": True, "ttl_seconds": 86400,
                        "stale_data_used": False},
            },
        }
        text = format_report(report)
        self.assertIn("SOURCE FRESHNESS: NVD cache fresh (0.0s old, 86400s TTL)", text)
        self.assertIn("SOURCE STATUS: NVD available", text)
        self.assertIn("never used to assert current status", text)


if __name__ == "__main__":
    unittest.main()
