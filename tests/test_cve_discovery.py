"""Offline tests for version-aware catalogue discovery and scoped Nmap XML."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from penx_app.intelligence import nvd_disk_cache
from penx_app.intelligence.cve_observations import (
    parse_nmap_services, parse_explicit_packages, normalize_cpe, github_ecosystem
)
from penx_app.intelligence.cve_engine import (
    applicability, version_applies, compare_versions, nvd_candidates,
    osv_candidates, github_candidates, discover, format_report, _cached_nvd,
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
   <port protocol="tcp" portid="80">
    <state state="closed"/>
    <service product="Example" version="1.0"><cpe>cpe:/a:x:y:1.0</cpe></service>
   </port>
  </ports>
 </host>
</nmaprun>"""

def record(cve="CVE-2024-9999", *, start="9.0", end="9.4",
           operator="OR", extra=None, vendor_ref=True):
    matches = [{"vulnerable": True,
                "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                "versionStartIncluding": start, "versionEndExcluding": end}]
    if extra:
        matches.append(extra)
    return {"cve": {
        "id": cve, "vulnStatus": "Analyzed",
        "configurations": [{"nodes": [{"operator": operator, "cpeMatch": matches}]}],
        "references": ([{"url":"https://example.org/security/fix",
                         "tags":["Vendor Advisory"]}] if vendor_ref else [])
    }}

def response(payload, status=200):
    res=Mock()
    res.status_code=status
    res.headers={}
    res.json.return_value=payload
    res.raise_for_status.return_value=None
    return res

class CveDiscoveryTests(unittest.TestCase):
    def setUp(self):
        # The NVD disk cache is enabled by default; keep these transport
        # tests from reading or writing the repository's real cache.
        self.temp = tempfile.TemporaryDirectory(prefix="penx-nvd-cache-")
        self.addCleanup(self.temp.cleanup)
        self.directory = patch.object(
            nvd_disk_cache, "CACHE_DIR", Path(self.temp.name))
        self.directory.start()
        self.addCleanup(self.directory.stop)
        _cached_nvd.cache_clear()
        self.addCleanup(_cached_nvd.cache_clear)

    def test_nmap_xml_extracts_concrete_cpe_and_skips_closed_ports(self):
        services = parse_nmap_services(SAMPLE_XML)
        self.assertEqual(len(services),1)
        self.assertEqual(services[0].port, "22/tcp")
        self.assertEqual(services[0].version, "9.2")
        self.assertEqual(services[0].cpe,
                         "cpe:2.3:a:openbsd:openssh:9.2:*:*:*:*:*:*:*")

    def test_nmap_malformed_or_hostile_xml_fails_closed(self):
        self.assertEqual(parse_nmap_services("<nmaprun><x></nmaprun>"), [])
        bad_xml = '<nmaprun><!DOCTYPE foo [<!ENTITY x "BOMB">]><host>&x;</host></nmaprun>'
        self.assertEqual(parse_nmap_services(bad_xml), [])
        self.assertEqual(parse_nmap_services("<nmaprun>"+" " * 2000001+"</nmaprun>"), [])
        xml = SAMPLE_XML.replace('version="9.2"','version="9.8"')
        self.assertEqual(parse_nmap_services(xml), [])

    def test_nmap_xml_file_and_text_both_preserved(self):
        from penx_app.scanners import tools
        def mock_scanner(command, **kwargs):
            self.assertIn("-oX", command)
            path = Path(command[command.index("-oX")+1])
            path.write_text(SAMPLE_XML.split("\n",1)[1],encoding="utf-8")
            self.assertEqual(command[-1], "example.test")
            return "PORT 22/tcp open ssh"
        with patch("penx_app.scanners.tools._executable",return_value="nmap"),patch("penx_app.scanners.tools.run_tool",side_effect=mock_scanner):
            result = tools.run_nmap("example.test")
        self.assertIn("PORT 22/tcp open", result)
        self.assertIn("<nmaprun", result)

    def test_version_ranges_and_unknown_syntax(self):
        match = {"versionStartIncluding":"1.2", "versionEndExcluding":"2.0"}
        self.assertTrue(version_applies("1.2",match,"*"))
        self.assertFalse(version_applies("2.0",match,"*"))
        self.assertFalse(version_applies("1.1.99",match,"*"))
        self.assertIsNone(version_applies("9.2p1",match,"*"))
        self.assertIsNone(compare_versions("1.2p1", "1.3"))

    def test_nested_configuration_and_platform_condition_are_not_confirmed(self):
        product = parse_nmap_services(SAMPLE_XML)[0]
        self.assertEqual(applicability(record()["cve"], product),
                         "version-match-needs-vendor-review")
        self.assertEqual(applicability(record(operator="AND")["cve"], product),
                         "conditional-platform-match")
        self.assertEqual(applicability(record(start="9.3")["cve"], product),
                         "no-match")
        self.assertEqual(applicability({"configurations":[]}, product), "unresolved")

    def test_nvd_query_contains_cpe_not_target_and_keeps_advisory_links(self):
        def fake_get(url, **kwargs):
            self.assertIn("services.nvd.nist.gov", url)
            self.assertIn("cpeName", kwargs["params"])
            self.assertNotIn("192.0.2.5", repr(kwargs))
            return response({"totalResults":1, "vulnerabilities":[record()]})
        with patch("penx_app.intelligence.cve_engine.requests.get",side_effect=fake_get):
            products = parse_nmap_services(SAMPLE_XML)
            matches, warning=nvd_candidates(products[0])
        self.assertEqual(warning,"")
        self.assertEqual(len(matches),1)
        self.assertEqual(matches[0]["id"],"CVE-2024-9999")
        self.assertEqual(matches[0]["status"],"version-match-needs-vendor-review")
        self.assertIn("https://example.org/security/fix",matches[0]["vendor_advisories"])

    def test_osv_queries_explicit_purl_and_github_uses_affects(self):
        purls=parse_explicit_packages("PKG: pkg:pypi/requests@2.31.0 and pkg:npm/left-pad@1.3.0")
        self.assertEqual(len(purls),2)
        self.assertEqual(purls[0].ecosystem,"PyPI")
        self.assertEqual(github_ecosystem(purls[0].purl),"pip")
        self.assertEqual(parse_explicit_packages("OpenSSH 9.2 httpd 2.4"),[])
        def fake_post(url,**kwargs):
            self.assertEqual(kwargs["json"]["package"]["purl"],"pkg:pypi/requests@2.31.0")
            return response({"vulns":[{"id":"GHSA-abcd-efgh-ijkl"}]})
        with patch("penx_app.intelligence.cve_engine.requests.post",side_effect=fake_post):
            found,warn=osv_candidates(purls[0])
        self.assertFalse(warn)
        self.assertEqual(found[0]["source"],"OSV")
        def fake_get(url,**kwargs):
            self.assertEqual(kwargs["params"]["ecosystem"],"pip")
            self.assertEqual(kwargs["params"]["affects"],"requests@2.31.0")
            return response([{"ghsa_id":"GHSA-abcd-efgh-ijkl","cve_id":"CVE-2024-9999",
                              "html_url":"https://github.com/advisories/GHSA-abcd-efgh-ijkl"}])
        with patch("penx_app.intelligence.cve_engine.requests.get",side_effect=fake_get):
            gh,warn=github_candidates(purls[0])
        self.assertEqual(gh[0]["source"],"GitHub Advisory")
        self.assertEqual(gh[0]["id"],"CVE-2024-9999")

    def test_catalogue_errors_are_visible_not_false_negative(self):
        import requests
        product=parse_nmap_services(SAMPLE_XML)[0]
        with patch("penx_app.intelligence.cve_engine.requests.get",side_effect=requests.Timeout()):
            candidates,warn=nvd_candidates(product)
        self.assertEqual(candidates,[])
        self.assertIn("unavailable",warn.lower())

    def test_integration_enriches_prompt_and_stores_candidates_without_fake_vulns(self):
        from penx_app.analysis import llm
        discovery={
            "observations":["Port tcp/22: SSH 9.2"],
            "candidates":[{
                "id":"CVE-2024-9999","source":"NVD",
                "status":"version-match-needs-vendor-review",
                "product":"OpenSSH","version":"9.2","port":"22/tcp",
                "evidence":"CPE 9.2","url":"https://nvd.nist.gov/vuln/detail/CVE-2024-9999",
                "vendor_advisories":[]
            }],
            "warnings":[]
        }
        def model(messages, settings=None):
            self.assertIn("CVE-2024-9999",messages[-1]["content"])
            return "RISK_LEVEL: LOW\nSUMMARY: No confirmed vulnerabilities"
        with patch("penx_app.analysis.llm.discover",return_value=discovery),\
             patch("penx_app.analysis.llm.ask_llm",side_effect=model),\
             patch("penx_app.analysis.llm.STRUCTURED_MODE","off"),\
             patch("penx_app.analysis.llm.self_review",return_value={"review":"","adjusted_risk":"","flags":[]}),\
             patch("penx_app.analysis.llm.verify_findings",side_effect=lambda records,*a,**kw: records),\
             patch("penx_app.analysis.llm.load_correction_rules",return_value=""):
            data=llm.analyse_target("example.test",SAMPLE_XML)
        self.assertIn("CVE-2024-9999",data["full_response"])
        self.assertEqual(data["vulnerabilities"],[])
        self.assertIn("NOT confirmed",format_report(discovery))

    def test_no_identifiers_means_no_queries(self):
        with patch("penx_app.intelligence.cve_engine.requests.get") as get,patch("penx_app.intelligence.cve_engine.requests.post") as post:
            rep=discover("Nothing detected")
            self.assertFalse(rep["candidates"])
            self.assertFalse(rep["observations"])
            get.assert_not_called()
            post.assert_not_called()

if __name__ == "__main__":
    unittest.main(verbosity=2)
