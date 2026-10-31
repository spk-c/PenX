"""Offline Shodan integration tests. Never contacts the target or external APIs."""
from __future__ import annotations

import json
import unittest
from unittest.mock import Mock, patch

import requests

from penx_app.application.scan_trends import compare_sessions, report_text
from penx_app.intelligence.shodan_enrichment import (
    SHODAN_INFO_URL, SHODAN_HOST_BASE, INTERNETDB_BASE,
    enrich_target, normalize_internetdb, resolve_public_ipv4, format_api_error,
)


def internetdb(ip: str, *, ports=None, cves=None):
    return {
        "ip": ip, "ports": ports if ports is not None else [80, 443],
        "cpes": ["cpe:/a:example:webserver:1.0"],
        "hostnames": ["example.test"], "tags": ["cdn"],
        "vulns": cves if cves is not None else ["CVE-2024-1234"],
    }


class ShodanTests(unittest.TestCase):
    def test_domain_dns_to_bounded_public_ipv4(self):
        with patch("dns.resolver.resolve", return_value=[
            "8.8.8.8", "192.168.1.1", "1.1.1.1", "9.9.9.9"
        ]) as dns:
            ips, description = resolve_public_ipv4("example.test", limit=2)
        self.assertEqual(ips, ["8.8.8.8", "1.1.1.1"])
        self.assertIn("up to 2", description)
        dns.assert_called_once_with("example.test", "A", lifetime=6)

    def test_rejects_private_reserved_ipv6_and_subnet(self):
        for address in ("127.0.0.1", "192.168.1.1", "198.51.100.42", "::1", "fe80::1"):
            urls = []
            result = enrich_target(address,
                                   lambda url, _urls=urls, **kw: _urls.append(url))
            self.assertEqual(urls, [])
            self.assertTrue(result and "skipped" in result[0])
        with patch("dns.resolver.resolve", return_value=["192.168.0.2"]):
            self.assertEqual(resolve_public_ipv4("lan.example")[0], [])

    def test_internetdb_no_key_and_record_bounded(self):
        calls = []
        def request(url, **kw):
            calls.append((url, kw))
            return internetdb("8.8.8.8", ports=[80, 443, 0, -1, 99999, True])
        with patch.dict("os.environ", {"PENX_SHODAN_API_KEY": ""}):
            result = enrich_target("8.8.8.8", request)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0], INTERNETDB_BASE + "8.8.8.8")
        self.assertEqual(calls[0][1], {"allow_redirects": False})
        self.assertIn("[SHODAN INTERNETDB RECORD]", result[0])
        record = json.loads(result[0].split("\n", 1)[1])
        self.assertEqual(record["ports"], [80, 443])
        self.assertIn("unverified", record["verification"])
        self.assertIn("CVE-2024-1234", record["vulns"])

    def test_domain_lookup_queries_only_external_index_ips(self):
        urls = []
        def fake(url, **kwargs):
            urls.append(url)
            return internetdb(url.rsplit("/", 1)[-1], cves=[])
        with patch("dns.resolver.resolve", return_value=["8.8.8.8", "1.1.1.1"]):
            result = enrich_target("example.test", fake, max_ips=2, include_paid=False)
        self.assertEqual(urls, [INTERNETDB_BASE + "8.8.8.8",
                                INTERNETDB_BASE + "1.1.1.1"])
        self.assertEqual(sum("[SHODAN INTERNETDB RECORD]" in row for row in result), 2)

    def test_optional_premium_status_and_key_never_displayed(self):
        secret = "SECRET-DO-NOT-LEAK"
        requests_seen = []
        def fake(url, **kwargs):
            requests_seen.append((url, kwargs))
            if url == SHODAN_INFO_URL:
                return {"plan": "member", "query_credits": 9, "unlocked": True}
            if url.startswith(SHODAN_HOST_BASE):
                return {"ip_str": "8.8.8.8", "ports": [443], "org": "Example Org",
                        "data": [{"port": 443, "transport": "tcp",
                                  "product": "nginx", "version": "1.25"}]}
            return internetdb("8.8.8.8")
        result = enrich_target("8.8.8.8", fake, api_key=secret)
        self.assertEqual(len(requests_seen), 3)
        self.assertTrue(all(v.get("allow_redirects") is False for _, v in requests_seen))
        self.assertTrue(all(v.get("params", {}).get("key") == secret
                            for url, v in requests_seen if url != INTERNETDB_BASE + "8.8.8.8"))
        self.assertIn("member", "\n".join(result))
        self.assertIn("nginx", "\n".join(result))
        self.assertNotIn(secret, repr(result))

    def test_api_errors_404_and_429_never_become_empty_scan(self):
        errors = []
        for code in (404, 401, 403, 402, 429):
            response = Mock(status_code=code)
            exc = requests.HTTPError("https://api.shodan.io/?key=PRIVATE", response=response)
            message = format_api_error(exc, "SHODAN")
            self.assertNotIn("PRIVATE", message)
            errors.append(message)
        self.assertIn("No indexed data", errors[0])
        self.assertIn("access denied", errors[2])
        self.assertIn("Rate limited", errors[-1])

    def test_opt_out_does_not_resolve_or_contact_external_sources(self):
        with patch("penx_app.intelligence.shodan_enrichment.resolve_public_ipv4",
                   side_effect=AssertionError("DNS should not be queried")):
            result = enrich_target("example.test", lambda *_a, **_kw:
                                   self.fail("External network should not be queried"),
                                   include_paid=False, free_enabled=False)
        self.assertIn("Disabled", result[0])

    def test_premium_429_stops_further_paid_calls_but_free_records_continue(self):
        urls = []
        def mock_api(url, **kw):
            urls.append(url)
            if url == SHODAN_INFO_URL:
                return {"plan": "member", "unlocked": True, "query_credits": 2}
            if url.startswith(SHODAN_HOST_BASE):
                raise requests.HTTPError(
                    "token=TOP_SECRET",
                    response=Mock(status_code=429)
                )
            return internetdb(url.rsplit("/", 1)[-1])
        with patch("penx_app.intelligence.shodan_enrichment.resolve_public_ipv4",
                   return_value=(["8.8.8.8", "1.1.1.1"], "from DNS")):
            result = enrich_target("example.test", mock_api, api_key="TOP_SECRET")
        self.assertEqual(sum(u.startswith(SHODAN_HOST_BASE) for u in urls), 1)
        self.assertEqual(sum(u.startswith(INTERNETDB_BASE) for u in urls), 2)
        self.assertIn("Rate limited (429)", "\n".join(result))
        self.assertNotIn("TOP_SECRET", "\n".join(result))

    def test_invalid_provider_responses_cannot_invent_a_cve(self):
        with self.assertRaises(ValueError):
            normalize_internetdb(internetdb("1.1.1.1"), "8.8.8.8")
        clean = normalize_internetdb(internetdb("8.8.8.8", cves=[
            "CVE-2024-1234", "BAD-THING", "<script>", 23
        ]), "8.8.8.8")
        self.assertEqual(clean["vulns"], ["CVE-2024-1234"])

    def test_shodan_scan_diff_separate_from_live_nmap_and_requires_same_ip(self):
        def session(number, ip, ports, cves):
            record = normalize_internetdb(internetdb(ip, ports=ports, cves=cves), ip)
            raw = "[PASSIVE-ONLY RECON]\n\n[SHODAN INTERNETDB RECORD]\n" + json.dumps(record)
            return {
                "history": (number, "example.test", "2026-10-14", "active"),
                "summary": (number, number, raw, "summary", "LOW"),
                "vulns": [],
            }
        before = session(1, "8.8.8.8", [80], ["CVE-2024-1234"])
        after = session(2, "8.8.8.8", [443], ["CVE-2025-9999"])
        diff = compare_sessions(before, after)
        self.assertFalse(diff["port_comparison_reliable"])
        self.assertEqual(diff["new_ports"], {})
        historical = diff["shodan_internetdb"]
        self.assertEqual(historical["new_indexed_ports"], [{"ip": "8.8.8.8", "port": 443}])
        self.assertEqual(historical["no_longer_indexed_ports"], [{"ip": "8.8.8.8", "port": 80}])
        self.assertEqual(historical["new_cve_candidates"], [
            {"ip": "8.8.8.8", "cve": "CVE-2025-9999"}])
        self.assertIn("external observations", report_text(diff))
        changed_ip = compare_sessions(before, session(3, "1.1.1.1", [443], []))
        self.assertEqual(changed_ip["shodan_internetdb"]["comparable_ips"], [])
        self.assertEqual(changed_ip["shodan_internetdb"]["no_longer_indexed_ports"], [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
