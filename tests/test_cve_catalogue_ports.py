"""Offline source-client injection regression tests for catalogue discovery."""
from __future__ import annotations

from contextlib import ExitStack
from unittest.mock import Mock, patch
import unittest

import requests

from penx_app.intelligence import cve_engine as cve
from penx_app.intelligence.cve_observations import parse_nmap_services, parse_explicit_packages


XML = """[NMAP STRUCTURED XML]
<nmaprun scanner="nmap"><host><ports><port protocol="tcp" portid="22">
<state state="open"/><service name="ssh" product="OpenSSH" version="9.2">
<cpe>cpe:/a:openbsd:openssh:9.2</cpe>
</service></port></ports></host></nmaprun>"""


def response(obj, status=200, retry="1"):
    value = Mock()
    value.status_code = status
    value.headers = {"Retry-After": retry}
    value.json.return_value = obj
    value.raise_for_status.return_value = None
    return value


class CataloguePortsTests(unittest.TestCase):
    def setUp(self):
        cve._cached_nvd.cache_clear()
        self.addCleanup(cve._cached_nvd.cache_clear)

    def test_injected_nvd_get_never_uses_global_network_or_caches(self):
        product = parse_nmap_services(XML)[0]
        client = Mock(return_value=response({"totalResults": 0, "vulnerabilities": []}))
        with ExitStack() as stack:
            for name in ("load_nvd_cache", "store_nvd_cache", "_memory_nvd"):
                stack.enter_context(patch.object(cve, name,
                    side_effect=AssertionError("unexpected production cache")))
            stack.enter_context(patch.object(cve.requests, "get",
                side_effect=AssertionError("real network")))
            found, warning = cve.nvd_candidates(product, http_get=client)
        self.assertEqual((found, warning), ([], ""))
        self.assertEqual(client.call_args.args, (cve.NVD,))
        self.assertEqual(client.call_args.kwargs["params"]["cpeName"], product.cpe)
        self.assertEqual(client.call_args.kwargs["timeout"], (3, 9))
        self.assertIs(client.call_args.kwargs["allow_redirects"], False)

    def test_rate_limit_retries_exactly_once_using_scoped_transport(self):
        client = Mock(side_effect=[
            response({}, status=429, retry="999"),
            response({"totalResults": 0, "vulnerabilities": []}),
        ])
        with patch.object(cve.requests, "get", side_effect=AssertionError("network")), \
             patch.object(cve.time, "sleep") as sleep:
            found, warning = cve.nvd_candidates(
                parse_nmap_services(XML)[0], http_get=client)
        self.assertEqual((found, warning), ([], ""))
        self.assertEqual(client.call_count, 2)
        self.assertTrue(all(call.kwargs["allow_redirects"] is False
                            for call in client.call_args_list))
        sleep.assert_called_once_with(1)

    def test_injected_osv_post_and_github_get_preserve_request_bounds(self):
        pkg = parse_explicit_packages("pkg:pypi/requests@2.31.0")[0]
        post = Mock(return_value=response({"vulns": [{"id": "OSV-TEST-1"}]}))
        get = Mock(return_value=response([{
            "cve_id": "CVE-2024-9999",
            "html_url": "https://github.com/advisories/GHSA-abcd-efgh-ijkl",
        }]))
        with patch.object(cve.requests, "post", side_effect=AssertionError("network")), \
             patch.object(cve.requests, "get", side_effect=AssertionError("network")):
            osv, owarn = cve.osv_candidates(pkg, http_post=post)
            gh, gwarn = cve.github_candidates(
                pkg, token="TEST-SECRET", http_get=get)
        self.assertEqual((owarn, gwarn), ("", ""))
        self.assertEqual([x["source"] for x in osv], ["OSV"])
        self.assertEqual([x["source"] for x in gh], ["GitHub Advisory"])
        self.assertEqual(post.call_args.args, (cve.OSV,))
        self.assertEqual(post.call_args.kwargs["json"]["package"]["purl"], pkg.purl)
        self.assertEqual(post.call_args.kwargs["timeout"], (3, 9))
        self.assertIs(post.call_args.kwargs["allow_redirects"], False)
        self.assertEqual(get.call_args.kwargs["params"]["ecosystem"], "pip")
        self.assertEqual(get.call_args.kwargs["headers"]["Authorization"],
                         "Bearer TEST-SECRET")
        self.assertIs(get.call_args.kwargs["allow_redirects"], False)

    def test_transport_timeouts_never_claim_clean_results_or_leak_tokens(self):
        product = parse_nmap_services(XML)[0]
        pkg = parse_explicit_packages("pkg:pypi/requests@2.31.0")[0]
        broken = Mock(side_effect=requests.Timeout("TOKEN-SECRET"))
        with patch.object(cve.requests, "get", side_effect=AssertionError("network")), \
             patch.object(cve.requests, "post", side_effect=AssertionError("network")):
            results = (
                cve.nvd_candidates(product, http_get=broken),
                cve.osv_candidates(pkg, http_post=broken),
                cve.github_candidates(pkg, token="TOKEN-SECRET", http_get=broken),
            )
        for rows, warning in results:
            self.assertEqual(rows, [])
            self.assertTrue(warning)
            self.assertNotIn("SECRET", warning)

    def test_discovery_uses_only_supplied_provider_ports(self):
        calls = []
        def nvd(product, **kwargs):
            calls.append("nvd")
            return ([{"id": "CVE-2024-9999", "product": product.label,
                      "version": product.version}], "NVD fixture warning")
        def osv(package, **kwargs):
            calls.append("osv")
            return ([], "")
        def gh(package, **kwargs):
            calls.append("github")
            return ([], "GitHub fixture warning")
        priority = Mock(side_effect=lambda rows: (rows, ["priority unknown"]))
        source = XML + "\npkg:pypi/requests@2.31.0"
        with ExitStack() as stack:
            for name in ("nvd_candidates", "osv_candidates", "github_candidates"):
                stack.enter_context(patch.object(cve, name,
                    side_effect=AssertionError("production lookup")))
            stack.enter_context(patch.object(cve.requests, "get",
                side_effect=AssertionError("network")))
            stack.enter_context(patch.object(cve.requests, "post",
                side_effect=AssertionError("network")))
            result = cve.discover(
                source, nvd_lookup=nvd, osv_lookup=osv, github_lookup=gh,
                priority_lookup=priority)
        self.assertEqual(calls, ["nvd", "osv", "github"])
        self.assertEqual(len(result["candidates"]), 1)
        self.assertEqual(result["candidates"][0]["id"], "CVE-2024-9999")
        self.assertIn("NVD fixture warning", result["warnings"])
        self.assertIn("GitHub fixture warning", result["warnings"])
        self.assertIn("priority unknown", result["warnings"])
        priority.assert_called_once()

    def test_disabled_discovery_does_not_invoke_any_provider(self):
        never = Mock(side_effect=AssertionError("unexpected client"))
        result = cve.discover(
            XML, enabled=False, nvd_lookup=never, osv_lookup=never,
            github_lookup=never, priority_lookup=never, vendor_lookup=never)
        self.assertEqual(result, {
            "observations": [], "candidates": [], "warnings": []})
        never.assert_not_called()


if __name__ == "__main__":
    unittest.main()
