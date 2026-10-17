"""Offline regression tests for report F-03 / F-04 catalogue and HTTP bounds."""
from __future__ import annotations

import unittest
from unittest.mock import Mock, patch

from penx_app.intelligence.cve_engine import applicability, nvd_candidates
from penx_app.intelligence.cve_observations import Product
from penx_app.intelligence import search


PRODUCT = Product("cpe:2.3:a:openbsd:openssh:9.2:*:*:*:*:*:*:*",
                  "OpenSSH", "9.2", "22/tcp", "ssh", "synthetic fixture")


class MalformedNvdBoundaryTests(unittest.TestCase):
    def test_nonstring_config_operators_and_wrong_containers_fail_closed(self):
        bad = [
            {"nodes": [{"operator": 42, "cpeMatch": []}]},
            {"operator": None, "nodes": []},
            {"operator": ["OR"], "nodes": []},
            {"nodes": "malformed"},
            {"nodes": [{"operator": "AND", "cpeMatch": {"fake": 1}}]},
            {"nodes": [{"children": 15}]},
            {"nodes": [{"cpeMatch": [{"criteria": 123}]}]},
        ]
        for config in bad:
            with self.subTest(config=config):
                result = applicability({"configurations": [config]}, PRODUCT)
                self.assertNotEqual(result, "version-match-needs-vendor-review")

    def test_malformed_candidate_does_not_abort_valid_nvd_candidate(self):
        valid = {
            "id": "CVE-2024-6387",
            "configurations": [{"nodes": [{"cpeMatch": [{
                "vulnerable": True,
                "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
            }]}]}],
            "metrics": {},
        }
        malformed = {
            "id": "CVE-2026-12345",
            "configurations": [{"nodes": [{"cpeMatch": [{
                "vulnerable": True,
                "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                "versionStartIncluding": [1, 2, 3],
            }]}]}],
            "references": 17,  # malformed NVD supplier metadata
        }
        response = Mock()
        response.json.return_value = {"vulnerabilities": [
            {"cve": malformed}, {"cve": valid},
        ], "totalResults": 2}
        response.status_code = 200
        response.headers = {}
        found, warning = nvd_candidates(
            PRODUCT, http_get=lambda *a, **k: response,
        )
        self.assertEqual([x["id"] for x in found], ["CVE-2024-6387"])
        self.assertTrue(warning)
        response.close.assert_called_once()


class BoundedExternalPageTests(unittest.TestCase):
    def fake(self, chunks, status=200):
        response = Mock()
        response.status_code = status
        response.encoding = "utf-8"
        response.iter_content.side_effect = lambda **kw: iter(chunks)
        response.raise_for_status.return_value = None
        return response

    def test_private_addresses_and_credentials_do_not_invoke_http(self):
        for url in (
            "http://example.org", "https://localhost/foo",
            "https://127.0.0.1/", "https://192.168.0.1/",
            "https://[::1]/", "https://secret@public.example.org/",
            "https://build-server.internal/index", "file:///etc/passwd",
        ):
            with self.subTest(url=url):
                get = Mock(side_effect=AssertionError("unexpected HTTP"))
                self.assertIn("blocked", search.fetch_page(url, http_get=get))
                get.assert_not_called()

    def test_oversized_stream_stops_before_loading_whole_response(self):
        response = self.fake([b"x" * 262144] * 3)
        get = Mock(return_value=response)
        msg = search.fetch_page("https://www.example.org/info", http_get=get)
        self.assertIn("exceeded 512 KiB", msg)
        self.assertTrue(get.call_args.kwargs["stream"])
        self.assertFalse(get.call_args.kwargs["allow_redirects"])
        response.close.assert_called_once()

    def test_redirect_is_not_followed_and_response_is_closed(self):
        response = self.fake([], status=302)
        result = search.fetch_page(
            "https://www.example.org/", http_get=lambda *args, **kw: response)
        self.assertIn("redirect", result.lower())
        response.iter_content.assert_not_called()
        response.close.assert_called_once()

    def test_bounded_html_extracts_text_and_closes_resource(self):
        response = self.fake([b"<html><p>hello</p><script>hidden</script></html>"])
        result = search.fetch_page(
            "https://www.example.org/info", http_get=lambda *args, **kw: response)
        self.assertEqual(result, "hello")
        response.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
