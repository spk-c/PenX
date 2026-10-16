"""Offline checks for complete CVE research pipeline and conservative reporting."""
import unittest
from unittest.mock import Mock, patch

from penx_app.intelligence import cve_engine as engine
from penx_app.intelligence import cve_priority
from penx_app.intelligence import vendor_status
from penx_app.intelligence import source_verification
from penx_app.intelligence.cve_observations import parse_nmap_services

XML = '<nmaprun><host><ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.2"><cpe>cpe:/a:openbsd:openssh:9.2</cpe></service></port></ports></host></nmaprun>'
CPE = "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"
OTHER = "cpe:2.3:o:debian:debian_linux:12:*:*:*:*:*:*:*"

def leaf(criteria=CPE, low="9.0", high="9.4"):
    return {"vulnerable":True,"criteria":criteria,
            "versionStartIncluding":low,"versionEndExcluding":high}

class AdvancedCveTests(unittest.TestCase):
    def test_complex_nvd_boolean_and_version_bounds(self):
        product = parse_nmap_services(XML)[0]
        def cfg(operator, items):
            return {"configurations":[{"nodes":[{"operator":operator,"cpeMatch":items}]}]}
        self.assertEqual(engine.applicability(cfg("OR",[leaf(),leaf(OTHER)]),product),"version-match-needs-vendor-review")
        self.assertEqual(engine.applicability(cfg("AND",[leaf(),leaf(OTHER)]),product),"conditional-platform-match")
        self.assertEqual(engine.applicability(cfg("AND",[leaf(low="9.3"),leaf(OTHER)]),product),"no-match")
        self.assertEqual(engine.applicability({"configurations":[{"nodes":[{"negate":True,"cpeMatch":[leaf()]}]}]},product),"conditional-platform-match")

    def test_cvss_priority_and_first_epss(self):
        metric={"cvssMetricV31":[{"type":"Primary","source":"nvd@nist.gov",
                "cvssData":{"baseScore":9.8,"version":"3.1","vectorString":"CVSS:3.1/AV:N"}}]}
        self.assertEqual(cve_priority.extract_cvss(metric)["cvss_score"],9.8)
        res=Mock();res.raise_for_status.return_value=None
        res.json.return_value={"data":[{"cve":"CVE-2024-12345","epss":"0.72",
                                       "percentile":"0.98","date":"2026-10-14"}]}
        with patch("penx_app.intelligence.cve_priority.requests.get",return_value=res) as get, \
             patch("penx_app.intelligence.cve_priority.load_cisa_kev",return_value={"CVE-2024-12345"}):
            found,warn=cve_priority.enrich_priority([
                {"id":"CVE-2024-12345","cvss_score":9.8},
                {"id":"GHSA-xxxx-yyyy-zzzz"}])
        self.assertEqual(warn,[])
        self.assertEqual(found[0]["priority_label"],"known-exploited")
        self.assertAlmostEqual(found[0]["epss"],0.72)
        self.assertEqual(get.call_args.kwargs["params"]["cve"],"CVE-2024-12345")

    def test_epss_failure_is_unknown_not_zero(self):
        import requests
        with patch("penx_app.intelligence.cve_priority.requests.get",side_effect=requests.Timeout()), \
             patch("penx_app.intelligence.cve_priority.load_cisa_kev",return_value=None):
            report,notes=cve_priority.enrich_priority([{"id":"CVE-2024-12345"}])
        self.assertNotIn("epss", report[0])
        self.assertEqual(report[0]["kev_status"],"unknown")
        self.assertGreaterEqual(len(notes),2)

    def test_vendor_ubuntu_release_filter(self):
        obj={"packages":[{"name":"openssh","statuses":[
            {"release_codename":"jammy","status":"released","description":"1:8.9p1-3ubuntu0.10"},
            {"release_codename":"noble","status":"needed","description":""}]}]}
        with patch("penx_app.intelligence.vendor_status.ubuntu_data",return_value=obj):
            rows=vendor_status.vendor_guidance({"id":"CVE-2024-6387"},distro_hint="ubuntu:jammy")
        self.assertEqual(len(rows),1)
        self.assertEqual(rows[0]["fixed_version"],"1:8.9p1-3ubuntu0.10")
        self.assertEqual(rows[0]["status"],"released")
        self.assertNotIn("installed_status",rows[0])

    def test_vendor_redhat_and_debian(self):
        obj={"package_state":[{"product_name":"Red Hat Enterprise Linux 9","fix_state":"Not affected",
                               "package_name":"openssh"}]}
        with patch("penx_app.intelligence.vendor_status.redhat_data",return_value=obj):
            rows=vendor_status.vendor_guidance({"id":"CVE-2024-6387"},distro_hint="rhel:9")
        self.assertEqual(rows[0]["status"],"Not affected")
        self.assertIn("security-tracker.debian.org",vendor_status.vendor_guidance(
            {"id":"CVE-2024-6387"},distro_hint="debian:bookworm")[0]["url"])

    def test_llm_refreshes_discovery_after_new_tool_output(self):
        import llm
        calls=[]
        def lookup(scan, **kwargs):
            calls.append(scan)
            return {"observations":["updated"] if len(calls)>1 else [],
                    "candidates":[],"warnings":[]}
        def fake_run(tool_calls, authorized_target=None, raw_collector=None, summarizer=None):
            raw_collector.append(XML)
            return "Nmap reported additional data"
        responses=["[TOOL: nmap example.test]", "RISK_LEVEL: LOW\nSUMMARY: Verified nothing"]
        with patch("llm.discover",side_effect=lookup), \
             patch("llm.run_tool_calls",side_effect=fake_run), \
             patch("llm.ask_llm",side_effect=responses), \
             patch("llm.self_review",return_value={"review":"","adjusted_risk":"","flags":[]}), \
             patch("llm.load_correction_rules",return_value=""), \
             patch("llm.STRUCTURED_MODE","off"), \
             patch("llm.VERIFY_SOURCES",False), \
             patch("llm.verify_findings",side_effect=lambda v,*a,**k:v):
            result=llm.analyse_target("example.test","Initial evidence")
        self.assertEqual(len(calls),2)
        self.assertIn("<nmaprun", result["raw_scan"])
        self.assertIn("updated", result["full_response"])

if __name__=="__main__":
    unittest.main(verbosity=2)
