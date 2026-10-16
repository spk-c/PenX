"""Call-scoped provider clients: strictly offline fail-closed research contracts."""
from __future__ import annotations

import json
import unittest
from unittest.mock import Mock, patch

import requests

from penx_app.intelligence import shodan_enrichment as shodan
from penx_app.intelligence import vendor_status as vendor
from penx_app.intelligence import wordpress_advisories as wordpress


def response(data):
    res = Mock()
    res.json.return_value = data
    res.raise_for_status.return_value = None
    return res


class VendorTransportContracts(unittest.TestCase):
    CVE = "CVE-2026-12345"

    def setUp(self):
        vendor.redhat_data.cache_clear()
        vendor.ubuntu_data.cache_clear()
        self.addCleanup(vendor.redhat_data.cache_clear)
        self.addCleanup(vendor.ubuntu_data.cache_clear)

    def test_injected_redhat_transport_does_not_touch_production_cache(self):
        calls = []
        def fake(url, **kwargs):
            calls.append((url, kwargs))
            return response({"package_state": [{"product_name": "RHEL 9",
                                                "package_name": "openssh",
                                                "fix_state": "Not affected"}]})
        with patch.object(vendor.requests, "get", side_effect=AssertionError("network")):
            injected = vendor.fetch_redhat_data(self.CVE, http_get=fake)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0], vendor.REDHAT + self.CVE + ".json")
        self.assertEqual(calls[0][1], {"timeout": (3, 8), "allow_redirects": False})
        self.assertEqual(vendor.redhat_data.cache_info().currsize, 0)
        self.assertEqual(injected["package_state"][0]["package_name"], "openssh")
        with patch.object(vendor.requests, "get",
                          return_value=response({"package_state": []})) as get:
            self.assertEqual(vendor.fetch_redhat_data(self.CVE), {"package_state": []})
            self.assertEqual(vendor.fetch_redhat_data(self.CVE), {"package_state": []})
            get.assert_called_once()
        self.assertEqual(vendor.redhat_data.cache_info().currsize, 1)

    def test_injected_ubuntu_timeout_maps_to_unavailable_without_cache(self):
        with patch.object(vendor.requests, "get", side_effect=AssertionError("network")):
            result = vendor.fetch_ubuntu_data(
                self.CVE, http_get=Mock(side_effect=requests.Timeout("fixture timeout")))
        self.assertIsNone(result)
        self.assertEqual(vendor.ubuntu_data.cache_info().currsize, 0)

    def test_vendor_guidance_uses_call_local_client_and_release_filter(self):
        calls = []
        def ubuntu(cve):
            calls.append(cve)
            return {"packages": [{"name": "openssh", "statuses": [
                {"release_codename": "noble", "status": "needed"},
                {"release_codename": "jammy", "status": "released",
                 "description": "1:8.9p1-3ubuntu0.10"},
            ]}]}
        with patch.object(vendor, "ubuntu_data",
                          side_effect=AssertionError("must not use default")):
            result = vendor.vendor_guidance(
                {"id": self.CVE}, distro_hint="ubuntu:jammy",
                ubuntu_lookup=ubuntu,
            )
        self.assertEqual(calls, [self.CVE])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["release"], "jammy")
        self.assertEqual(result[0]["fixed_version"], "1:8.9p1-3ubuntu0.10")
        self.assertNotIn("installed_status", result[0])

    def test_vendor_guidance_handles_unavailable_lookup_conservatively(self):
        result = vendor.vendor_guidance(
            {"id": self.CVE}, distro_hint="rhel:9",
            redhat_lookup=lambda _cve: None,
        )
        self.assertEqual(result[0]["status"], "unavailable")


class WordpressTransportContracts(unittest.TestCase):
    EVIDENCE = "MetaGenerator[Elementor 3.2.1]"

    def test_injection_sends_only_package_identifier_and_not_scan_text(self):
        raw = "secret target.invalid " + self.EVIDENCE
        seen = []
        def fake(url, **kwargs):
            seen.append((url, kwargs))
            return response([{"cve_id": "CVE-2026-12345",
                              "html_url": "https://github.com/advisories/GHSA-test-test-test",
                              "vulnerabilities": []}])
        with patch.object(wordpress.requests, "get",
                          side_effect=AssertionError("network")):
            result = wordpress.research_plugins(raw, token="LOCAL-DUMMY",
                                                http_get=fake)
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0][0], wordpress.GH_API)
        self.assertEqual(seen[0][1]["params"]["affects"], "wpackagist-plugin/elementor")
        self.assertIs(seen[0][1]["allow_redirects"], False)
        self.assertEqual(seen[0][1]["timeout"], (3, 8))
        self.assertNotIn("target.invalid", repr(seen))
        self.assertNotIn("target.invalid", json.dumps(result))
        self.assertNotIn("LOCAL-DUMMY", json.dumps(result))
        self.assertEqual(result["candidates"][0]["status"],
                         "version-range-requires-vendor-review")

    def test_malformed_and_timeout_provider_responses_are_unavailable(self):
        for get in (lambda *_a, **_kw: response({"unexpected": True}),
                    Mock(side_effect=requests.Timeout("SECRET-DO-NOT-LEAK"))):
            with self.subTest(client=get):
                result = wordpress.research_plugins(self.EVIDENCE, http_get=get)
                self.assertEqual(result["checks"][0]["status"], "unavailable")
                self.assertEqual(result["candidates"], [])
                self.assertNotIn("SECRET-DO-NOT-LEAK", json.dumps(result))

    def test_disabled_lookup_never_invokes_injected_transport(self):
        client = Mock(side_effect=AssertionError("network"))
        result = wordpress.research_plugins(self.EVIDENCE, enabled=False,
                                            http_get=client)
        self.assertEqual(result["checks"][0]["status"], "disabled")
        client.assert_not_called()

    def test_limit_is_bounded_in_request_and_consumption(self):
        clients = []
        def fake(url, **kwargs):
            clients.append(kwargs)
            return response([{"cve_id": f"CVE-2026-{i+10000}",
                              "html_url": "https://github.com/advisories/GHSA-test-test-test"}
                             for i in range(80)])
        result = wordpress.research_plugins(self.EVIDENCE, limit=100, http_get=fake)
        self.assertEqual(clients[0]["params"]["per_page"], 20)
        self.assertEqual(len(result["candidates"]), 20)


class ShodanDnsTransportContracts(unittest.TestCase):
    def test_public_ipv4_resolver_is_call_scoped_and_bounded(self):
        seen = []
        def resolver(host, kind, *, lifetime):
            seen.append((host, kind, lifetime))
            return ["192.168.1.10", "8.8.8.8", "1.1.1.1", "9.9.9.9"]
        with patch("dns.resolver.resolve", side_effect=AssertionError("real DNS")):
            ips, note = shodan.resolve_public_ipv4(
                "fixture.invalid", limit=2, dns_resolve=resolver)
        self.assertEqual(ips, ["8.8.8.8", "1.1.1.1"])
        self.assertEqual(seen, [("fixture.invalid", "A", 6)])
        self.assertIn("2 public DNS", note)

    def test_enrichment_resolver_and_query_client_are_both_injected(self):
        resolved = []
        requested = []
        def ips(host, limit):
            resolved.append((host, limit))
            return ["8.8.8.8"], ""
        def query(url, **kwargs):
            requested.append((url, kwargs))
            return {"ip": "8.8.8.8", "ports": [443], "vulns": []}
        with patch.object(shodan, "resolve_public_ipv4",
                          side_effect=AssertionError("real resolver")):
            data = shodan.enrich_target(
                "fixture.invalid", query, include_paid=False, resolve_ips=ips)
        self.assertEqual(resolved, [("fixture.invalid", 3)])
        self.assertEqual(requested, [(shodan.INTERNETDB_BASE + "8.8.8.8",
                                     {"allow_redirects": False})])
        self.assertIn("unverified", "\n".join(data))
        self.assertIn("not a confirmed vulnerability", json.dumps(data).lower())

    def test_untrusted_resolver_cannot_send_private_or_reserved_ips(self):
        query = Mock(side_effect=AssertionError("private IP must not be queried"))
        result = shodan.enrich_target(
            "fixture.invalid", query, include_paid=False,
            resolve_ips=lambda *_: (["127.0.0.1", "192.0.2.123", "not-an-ip"], ""),
        )
        query.assert_not_called()
        self.assertIn("skipped", result[0])

    def test_injected_vendor_timeout_is_unavailable_not_negative_evidence(self):
        result = vendor.vendor_guidance(
            {"id": "CVE-2026-12345"}, distro_hint="rhel:9",
            redhat_lookup=Mock(side_effect=requests.Timeout("hidden token")),
        )
        self.assertEqual(result[0]["status"], "unavailable")
        self.assertNotIn("hidden token", json.dumps(result))

    def test_disabled_shodan_never_invokes_either_client(self):
        resolver = Mock(side_effect=AssertionError("must stay disabled"))
        query = Mock(side_effect=AssertionError("must stay disabled"))
        result = shodan.enrich_target(
            "fixture.invalid", query, include_paid=False, free_enabled=False,
            resolve_ips=resolver)
        self.assertIn("Disabled", result[0])
        resolver.assert_not_called()
        query.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
