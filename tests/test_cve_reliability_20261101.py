"""Offline regressions for bounded CVE research and provider isolation."""
from __future__ import annotations

from collections import deque
import json
import unittest
from unittest.mock import Mock, patch

import requests

from penx_app.intelligence import cve_engine as cve
from penx_app.intelligence.cve_observations import parse_nmap_services, parse_explicit_packages


XML = """[NMAP STRUCTURED XML]
<nmaprun scanner="nmap"><host><ports><port protocol="tcp" portid="22">
<state state="open"/><service name="ssh" product="OpenSSH" version="9.2">
<cpe>cpe:/a:openbsd:openssh:9.2</cpe>
</service></port></ports></host></nmaprun>"""
SOURCE = XML + "\npkg:pypi/requests@2.31.0"


def response(payload: object, *, status: int = 200, retry_after: str = "6"):
    r = Mock()
    r.status_code = status
    r.headers = {"Retry-After": retry_after}
    r.json.return_value = payload
    r.raise_for_status.side_effect = None
    return r


class CveReliabilityTests(unittest.TestCase):
    def test_nvd_public_budget_is_a_sliding_thirty_second_window(self):
        # Synthetic time, no calls to actual NVD and no real sleeping.
        clock = [100.0]
        sleeps = []
        with cve._NVD_RATE_LOCK:
            original = cve._NVD_REQUESTS[False]
            cve._NVD_REQUESTS[False] = deque()
        try:
            def sleep(seconds):
                sleeps.append(seconds)
                clock[0] += seconds
            with patch.object(cve.time, "monotonic", side_effect=lambda: clock[0]), \\
                 patch.object(cve.time, "sleep", side_effect=sleep):
                for _ in range(6):
                    cve._nvd_before_request(has_key=False)
            self.assertEqual(len(sleeps), 1)
            self.assertAlmostEqual(sleeps[0], 30.0)
            self.assertEqual(len(cve._NVD_REQUESTS[False]), 1)
        finally:
            with cve._NVD_RATE_LOCK:
                cve._NVD_REQUESTS[False] = original

    def test_retry_after_respected_without_extra_or_unbounded_retry(self):
        client = Mock(side_effect=[
            response({}, status=429, retry_after="12"),
            response({"items": []}),
        ])
        with patch.object(cve.time, "sleep") as sleep:
            value = cve._get("https://api.example.test/", params={}, headers={}, http_get=client)
        self.assertEqual(value, {"items": []})
        self.assertEqual(client.call_count, 2)
        sleep.assert_called_once_with(12.0)
        self.assertEqual(cve._retry_after_seconds("9999"), 30.0)
        self.assertEqual(cve._retry_after_seconds("nan"), 6.0)

    def test_real_responses_reject_oversized_json_before_parsing(self):
        raw = requests.Response()
        raw.status_code = 200
        raw._content = json.dumps({"blob": "x" * 100}).encode("utf-8")
        raw._content_consumed = True
        with patch.object(cve, "MAX_CATALOGUE_RESPONSE_BYTES", 32):
            with self.assertRaisesRegex(ValueError, "exceeds size limit"):
                cve._bounded_json(raw)

    def test_one_broken_lookup_does_not_discard_other_sources(self):
        package = parse_explicit_packages(SOURCE)[0]
        def fail(*args, **kwargs):
            raise RuntimeError("broken custom lookup")
        output = cve.discover(
            SOURCE, nvd_lookup=fail,
            osv_lookup=lambda pkg, **kw: ([{
                "id": "OSV-OK", "product": pkg.name, "version": pkg.version}], ""),
            github_lookup=fail,
            priority=False,
        )
        self.assertEqual([v["id"] for v in output["candidates"]], ["OSV-OK"])
        self.assertTrue(any("NVD unavailable" in w for w in output["warnings"]))
        self.assertTrue(any("GitHub Advisories unavailable" in w for w in output["warnings"]))

    def test_candidate_display_limit_is_visible(self):
        product = parse_nmap_services(XML)[0]
        rows = [{"id": "CVE-2024-0001", "product": product.label,
                 "version": product.version},
                {"id": "CVE-2024-0002", "product": product.label,
                 "version": product.version}]
        result = cve.discover(
            XML, max_results=1,
            nvd_lookup=lambda p, **kw: (rows, ""),
            priority=False,
        )
        self.assertEqual(len(result["candidates"]), 1)
        self.assertTrue(any("result limit reached" in w for w in result["warnings"]))


if __name__ == "__main__":
    unittest.main()
