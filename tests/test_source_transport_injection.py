"""Offline source-transport injection contracts (no live HTTP, search or scanner)."""
from __future__ import annotations

import unittest
from unittest.mock import MagicMock, Mock, patch

import requests

from penx_app.intelligence import search, source_verification as verify


CVE = "CVE-2024-6387"


class SourceVerificationInjectionTests(unittest.TestCase):
    def setUp(self):
        verify._nvd_cache.clear()
        verify._kev_cache = None

    def test_injected_nvd_transport_does_not_read_or_write_process_cache(self):
        verify._nvd_cache[CVE] = "not-listed"
        response = Mock()
        response.json.return_value = {"vulnerabilities": [{"cve": {"id": CVE}}]}
        get = Mock(return_value=response)
        self.assertEqual(verify.lookup_nvd(CVE, api_key="fixture-key", get=get), "listed")
        self.assertEqual(verify._nvd_cache[CVE], "not-listed")
        args, kwargs = get.call_args
        self.assertEqual(args, (verify.NVD_API,))
        self.assertEqual(kwargs["params"], {"cveId": CVE})
        self.assertEqual(kwargs["headers"]["apiKey"], "fixture-key")
        self.assertFalse(kwargs["allow_redirects"])
        self.assertEqual(kwargs["timeout"], (3, 7))

    def test_injected_nvd_timeout_is_unavailable_and_not_cached(self):
        get = Mock(side_effect=requests.Timeout("offline"))
        self.assertEqual(verify.lookup_nvd(CVE, get=get), "unavailable")
        self.assertNotIn(CVE, verify._nvd_cache)

    def test_applicability_injected_transport_does_not_send_raw_scan(self):
        response = Mock()
        response.json.return_value = {"vulnerabilities": [{"cve": {"id": CVE}}]}
        get = Mock(return_value=response)
        raw = "TEST PRIVATE HOST 192.0.2.123"
        with patch("penx_app.intelligence.cve_observations.parse_nmap_services",
                   return_value=[object()]), patch(
                       "penx_app.intelligence.cve_engine.applicability",
                       return_value="no-match"):
            result = verify.verify_nvd_applicability(CVE, raw, get=get)
        self.assertIn("no-match", result)
        self.assertNotIn("192.0.2.123", repr(get.call_args))
        self.assertFalse(get.call_args.kwargs["allow_redirects"])

    def test_cisa_injected_transport_bypasses_cache_and_rejects_bad_schema(self):
        verify._kev_cache = {"CVE-2021-44228"}
        response = Mock()
        response.json.return_value = {"vulnerabilities": [{"cveID": CVE}]}
        get = Mock(return_value=response)
        self.assertEqual(verify.load_cisa_kev(get=get), {CVE})
        self.assertEqual(verify._kev_cache, {"CVE-2021-44228"})
        self.assertFalse(get.call_args.kwargs["allow_redirects"])
        response.json.return_value = {"vulnerabilities": "not a list"}
        self.assertIsNone(verify.load_cisa_kev(get=get))

    def test_verify_findings_can_use_all_injected_clients_without_network(self):
        finding = {
            "vuln_name": CVE, "confidence": "confirmed",
            "description": "Synthetic finding", "evidence": "invented evidence",
        }
        nvd = Mock(return_value="listed")
        applicability = Mock(return_value="unknown")
        kev = Mock(return_value={CVE})
        with patch.object(verify.requests, "get", side_effect=AssertionError("unexpected HTTP")):
            results = verify.verify_findings(
                [finding], "Unrelated scanner output", nvd_api_key="fixture-key",
                nvd_lookup=nvd, applicability_lookup=applicability, kev_loader=kev,
            )
        self.assertIs(results[0], finding)
        self.assertEqual(finding["confidence"], "possible")
        self.assertIn("Scanner evidence: NOT confirmed", finding["description"])
        self.assertIn("NVD listed", finding["description"])
        self.assertIn("CISA KEV listed", finding["description"])
        nvd.assert_called_once_with(CVE, api_key="fixture-key")
        applicability.assert_called_once_with(
            CVE, "Unrelated scanner output", api_key="fixture-key"
        )
        kev.assert_called_once()

    def test_disabled_source_verification_never_invokes_any_client(self):
        entry = {"vuln_name": CVE, "description": "Synthetic"}
        nvd, applicability, kev = Mock(), Mock(), Mock()
        self.assertEqual(verify.verify_findings(
            [entry], "", enabled=False, nvd_lookup=nvd,
            applicability_lookup=applicability, kev_loader=kev), [entry])
        for client in (nvd, applicability, kev):
            client.assert_not_called()


class PublicSourceSearchInjectionTests(unittest.TestCase):
    def test_ddgs_factory_injection_and_bounded_result(self):
        ddgs = MagicMock()
        ddgs.__enter__.return_value.text.return_value = [
            {"title": "Example", "href": "https://example.test", "body": "safe fixture"}
        ]
        factory = Mock(return_value=ddgs)
        result = search.web_search("fixture", max_results=2, ddgs_factory=factory)
        self.assertIn("safe fixture", result)
        ddgs.__enter__.return_value.text.assert_called_once_with(
            "fixture", max_results=2
        )
        factory.assert_called_once()

    def test_ddgs_failure_returns_non_evidence_warning(self):
        factory = Mock(side_effect=RuntimeError("offline"))
        self.assertTrue(search.web_search("fixture", ddgs_factory=factory).startswith("[!]"))

    def test_html_fetch_injection_removes_scripts_and_truncates(self):
        response = Mock(text="<html><script>ignore()</script><p>Visible</p><p>Text</p></html>")
        get = Mock(return_value=response)
        with patch.object(search.requests, "get", side_effect=AssertionError("unexpected HTTP")):
            output = search.fetch_page("https://example.test/page", max_chars=7, http_get=get)
        self.assertIn("Visible", output)
        self.assertIn("[truncated at 7 chars]", output)
        self.assertNotIn("ignore()", output)
        self.assertEqual(get.call_args.args, ("https://example.test/page",))
        self.assertEqual(get.call_args.kwargs["timeout"], 15)

    def test_html_fetch_injected_timeout_returns_warning(self):
        output = search.fetch_page("https://example.test", http_get=Mock(
            side_effect=requests.Timeout("offline")))
        self.assertEqual(output, "[!] Page fetch timed out.")

    def test_cve_dispatch_injects_search_and_fixed_mitre_fetch(self):
        web = Mock(return_value="search fixture")
        page = Mock(return_value="mitre fixture")
        result = search.handle_search_dispatch(
            f"research {CVE}", general_search=web, page_fetch=page,
        )
        self.assertIn("search fixture", result)
        self.assertIn("mitre fixture", result)
        web.assert_called_once_with(
            f"{CVE} vulnerability exploit details", max_results=3
        )
        page.assert_called_once_with(
            f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={CVE}",
            max_chars=2000,
        )

    def test_fix_exploit_and_general_dispatch_share_injected_search(self):
        web = Mock(return_value="search fixture")
        self.assertEqual(search.handle_search_dispatch(
            "fix SSH configuration", general_search=web), "search fixture")
        self.assertIn("how to fix", web.call_args.args[0])
        self.assertEqual(search.handle_search_dispatch(
            "apache exploit", general_search=web), "search fixture")
        self.assertIn("exploit poc github", web.call_args.args[0])
        self.assertEqual(search.handle_search_dispatch(
            "default query", general_search=web), "search fixture")
        self.assertEqual(web.call_args.args[0], "default query")


if __name__ == "__main__":
    unittest.main(verbosity=2)
