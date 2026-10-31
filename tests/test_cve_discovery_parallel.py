"""Offline contracts for parallel CVE catalogue discovery.

`discover()` fetches NVD on the calling thread (shared public rate limit)
while OSV and GitHub Advisories queries run on a bounded pool. These tests
pin the observable contract: results and warnings are absorbed in the same
deterministic order as the previous sequential implementation, sources stay
isolated, and the fetches actually overlap instead of serializing.
"""
from __future__ import annotations

import threading
import time
import unittest
from unittest import mock

from penx_app.intelligence import cve_engine as cve
from penx_app.intelligence.cve_observations import (
    parse_explicit_packages,
    parse_nmap_services,
)

XML = """[NMAP STRUCTURED XML]
<nmaprun scanner="nmap"><host><ports>
<port protocol="tcp" portid="22"><state state="open"/>
<service name="ssh" product="OpenSSH" version="9.2">
<cpe>cpe:/a:openbsd:openssh:9.2</cpe>
</service></port>
<port protocol="tcp" portid="80"><state state="open"/>
<service name="http" product="Apache" version="2.4.58">
<cpe>cpe:/a:apache:http_server:2.4.58</cpe>
</service></port>
</ports></host></nmaprun>"""

SOURCE = XML + "\npkg:pypi/requests@2.31.0\npkg:pypi/urllib3@1.26.0"


def _recorded_fake(results_by_key, calls, lock, sleep_seconds=0.0):
    def fake(subject, **kwargs):
        with lock:
            calls.append(subject)
        if sleep_seconds:
            time.sleep(sleep_seconds)
        return results_by_key[subject]
    return fake


class ParallelDiscoveryContracts(unittest.TestCase):
    def _run(self, products, packages, nvd_map, osv_map, gh_map, sleep=0.0):
        lock = threading.Lock()
        nvd_calls, osv_calls, gh_calls = [], [], []
        result = cve.discover(
            SOURCE,
            nvd_lookup=_recorded_fake(nvd_map, nvd_calls, lock, sleep),
            osv_lookup=_recorded_fake(osv_map, osv_calls, lock, sleep),
            github_lookup=_recorded_fake(gh_map, gh_calls, lock, sleep),
            priority_lookup=lambda rows: (rows, []),
        )
        return result, nvd_calls, osv_calls, gh_calls

    def test_results_and_warnings_absorb_in_deterministic_order(self):
        products = parse_nmap_services(SOURCE, max_services=12)
        packages = parse_explicit_packages(SOURCE, max_packages=12)
        nvd_map = {
            p: ([{"id": f"NVD-{p.label}", "product": p.label,
                 "version": p.version}], f"NVD warn {p.label}")
            for p in products
        }
        osv_map = {
            p: ([{"id": f"OSV-{p.purl}", "product": p.purl, "version": "1.0"}],
                f"OSV warn {p.purl}")
            for p in packages
        }
        gh_map = {
            p: ([{"id": f"GH-{p.purl}", "product": p.purl, "version": "1.0"}],
                f"GH warn {p.purl}")
            for p in packages
        }
        result, nvd_calls, osv_calls, gh_calls = self._run(
            products, packages, nvd_map, osv_map, gh_map)
        # NVD queries stay sequential on the calling thread, in product order.
        self.assertEqual([c.label for c in nvd_calls], [p.label for p in products])
        # OSV/GitHub queries may complete in any order on the pool...
        self.assertEqual(sorted(osv_calls, key=lambda c: c.purl),
                         sorted(packages, key=lambda c: c.purl))
        self.assertEqual(sorted(gh_calls, key=lambda c: c.purl),
                         sorted(packages, key=lambda c: c.purl))
        # ...but absorption order is deterministic: NVD by product, then per
        # package index OSV before GitHub.
        self.assertEqual([c["id"] for c in result["candidates"]], [
            f"NVD-{p.label}" for p in products
        ] + [
            id_ for p in packages for id_ in (f"OSV-{p.purl}", f"GH-{p.purl}")
        ])
        self.assertEqual(result["warnings"], [
            f"NVD warn {p.label}" for p in products
        ] + [
            warn for p in packages
            for warn in (f"OSV warn {p.purl}", f"GH warn {p.purl}")
        ])

    def test_duplicate_id_keeps_first_source_position(self):
        products = parse_nmap_services(SOURCE, max_services=12)
        packages = parse_explicit_packages(SOURCE, max_packages=12)
        # The dedupe key is (id, product, version); identical triples from
        # different sources must collapse to the first absorbed one.
        shared = {"id": "CVE-2024-0001", "product": "shared", "version": "1.0"}
        nvd_map = {p: ([dict(shared, source="NVD")], "") for p in products}
        osv_map = {p: ([dict(shared, source="OSV")], "") for p in packages}
        gh_map = {p: ([dict(shared, source="GitHub")], "") for p in packages}
        result, _, _, _ = self._run(products, packages, nvd_map, osv_map, gh_map)
        self.assertEqual([c["id"] for c in result["candidates"]],
                         ["CVE-2024-0001"])
        # First occurrence wins: the NVD record, absorbed first.
        self.assertEqual(result["candidates"][0]["source"], "NVD")

    def test_source_warning_isolates_failure(self):
        products = parse_nmap_services(SOURCE, max_services=12)
        packages = parse_explicit_packages(SOURCE, max_packages=12)
        nvd_map = {p: ([], "") for p in products}
        osv_map = {
            packages[0]: ([], f"OSV unavailable for {packages[0].purl}"),
            packages[1]: ([{"id": "OSV-OK", "product": packages[1].purl,
                            "version": "1.0"}], ""),
        }
        gh_map = {p: ([], "") for p in packages}
        result, _, _, _ = self._run(products, packages, nvd_map, osv_map, gh_map)
        self.assertEqual([c["id"] for c in result["candidates"]], ["OSV-OK"])
        self.assertIn(f"OSV unavailable for {packages[0].purl}",
                      result["warnings"])

    def test_fetches_overlap_instead_of_serializing(self):
        products = parse_nmap_services(SOURCE, max_services=12)
        packages = parse_explicit_packages(SOURCE, max_packages=12)
        nvd_map = {p: ([], "") for p in products}
        osv_map = {p: ([], "") for p in packages}
        gh_map = {p: ([], "") for p in packages}
        sleep = 0.2
        total_calls = len(products) + 2 * len(packages)
        self.assertEqual(total_calls, 6)

        # Self-calibrated sequential floor: run the same work serially.
        lock = threading.Lock()
        noop_calls = []
        sequential = time.perf_counter()
        for key_map, subjects in ((nvd_map, products),):
            for subject in subjects:
                _recorded_fake(key_map, noop_calls, lock, sleep)(subject)
        for subject in packages:
            _recorded_fake(osv_map, noop_calls, lock, sleep)(subject)
            _recorded_fake(gh_map, noop_calls, lock, sleep)(subject)
        sequential_wall = time.perf_counter() - sequential

        start = time.perf_counter()
        self._run(products, packages, nvd_map, osv_map, gh_map, sleep=sleep)
        parallel_wall = time.perf_counter() - start

        # With three pool workers plus the NVD lane the wall time must be a
        # clear fraction of the sequential floor, not merely "eventually".
        self.assertLess(parallel_wall, sequential_wall * 0.7)

    def test_empty_inputs_do_no_lookups(self):
        never = mock.Mock(side_effect=AssertionError("unexpected client"))
        result = cve.discover(
            "[NMAP STRUCTURED XML]\n<nmaprun scanner=\"nmap\"></nmaprun>",
            nvd_lookup=never, osv_lookup=never, github_lookup=never,
            priority_lookup=lambda rows: (rows, []),
        )
        self.assertEqual(result, {"observations": [], "candidates": [],
                                  "warnings": []})
        never.assert_not_called()


if __name__ == "__main__":
    unittest.main()
