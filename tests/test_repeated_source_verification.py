"""Rerunning source checks must not accumulate historical model annotations.

No network requests: source verification clients are injected mocks.
"""
from __future__ import annotations

import copy
import threading
import unittest
from unittest.mock import Mock, patch

from penx_app.intelligence import source_verification as source
from penx_app.intelligence.source_verification import verify_findings


FIRST = "CVE-2024-6387"
SECOND = "CVE-2026-12345"


def verify(findings, *, cves=None):
    cves = {FIRST} if cves is None else cves
    return verify_findings(
        findings, "443/tcp open HTTPS",
        nvd_lookup=lambda _cve, **kw: "listed",
        applicability_lookup=lambda _cve, *_a, **kw: "unknown",
        kev_loader=lambda: cves,
    )


class SourceVerificationRepeatabilityTests(unittest.TestCase):
    def test_double_verification_is_idempotent(self):
        finding = {
            "vuln_name": "OpenSSH finding " + FIRST,
            "description": "Review package version",
            "evidence": "443/tcp open HTTPS",
            "confidence": "possible",
        }
        result = verify([finding])
        once = copy.deepcopy(result)
        verify(result)
        self.assertEqual(result, once)
        self.assertEqual(finding["description"].count("Reference checks ("), 1)
        self.assertEqual(finding["description"].count("CISA KEV listed"), 1)

    def test_empty_original_description_is_also_idempotent(self):
        finding = {
            "vuln_name": FIRST, "description": "",
            "evidence": "Not supported evidence", "confidence": "possible",
        }
        verify([finding])
        once = finding["description"]
        verify([finding])
        self.assertEqual(finding["description"], once)

    def test_old_cve_annotations_do_not_retain_removed_identifiers(self):
        finding = {
            "vuln_name": FIRST,
            "description": "A synthetic finding",
            "evidence": "443/tcp open HTTPS",
            "confidence": "possible",
        }
        verify([finding], cves={FIRST})
        finding["vuln_name"] = SECOND
        verify([finding], cves={SECOND})
        self.assertIn(SECOND, finding["description"])
        self.assertNotIn(FIRST, finding["description"])
        self.assertEqual(finding["description"].count("Reference checks ("), 1)
        self.assertEqual(finding["source_checks"][-1].split(":")[0], SECOND)

    def test_only_exact_generated_footer_is_replaced(self):
        finding = {
            "vuln_name": FIRST,
            "description": "Operator text before source checks",
            "evidence": "443/tcp open HTTPS",
            "confidence": "possible",
        }
        verify([finding])
        finding["description"] += "\nOperator comment added after review"
        verify([finding])
        self.assertIn("Operator comment added after review", finding["description"])
        # Refuse to strip arbitrary user comments along with generated data.
        self.assertGreaterEqual(finding["description"].count("Reference checks ("), 2)

    def test_client_lookup_still_injected_on_repeated_calls(self):
        finding = {
            "vuln_name": FIRST,
            "description": "Operator note",
            "evidence": "443/tcp open HTTPS",
        }
        nvd = Mock(return_value="listed")
        for _ in range(2):
            verify_findings(
                [finding], "443/tcp open HTTPS",
                nvd_lookup=nvd,
                applicability_lookup=lambda *_args, **_kw: "unknown",
                kev_loader=lambda: {FIRST},
            )
        self.assertEqual(nvd.call_count, 2)
        self.assertEqual(finding["description"].count("Reference checks ("), 1)

    def test_concurrent_first_lookups_leave_a_consistent_cache(self):
        # The first lookup of a CVE runs the network path. Concurrent first
        # lookups must all observe the same result and leave the process
        # cache consistent (status and timestamp written together).
        payload = {"vulnerabilities": [{"cve": {"id": FIRST}}]}
        client = Mock()
        client.return_value.json.return_value = payload
        client.return_value.raise_for_status.return_value = None
        clock = [100.0]

        def fake_sleep(seconds):
            clock[0] += seconds

        original_cache = source._nvd_cache.copy()
        original_cache_time = source._nvd_cache_time.copy()
        try:
            with patch.object(source.time, "monotonic",
                              side_effect=lambda: clock[0]), \
                 patch.object(source.time, "sleep", side_effect=fake_sleep), \
                 patch.object(source.requests, "get", client):
                results = []
                errors = []

                def worker():
                    try:
                        results.append(source.lookup_nvd(FIRST))
                    except BaseException as exc:
                        errors.append(exc)

                threads = [threading.Thread(target=worker) for _ in range(8)]
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join(timeout=15)
                self.assertEqual(errors, [])
                self.assertEqual(results, ["listed"] * 8)
                self.assertEqual(source._nvd_cache.get(FIRST), "listed")
        finally:
            source._nvd_cache.clear()
            source._nvd_cache_time.clear()
            source._nvd_cache.update(original_cache)
            source._nvd_cache_time.update(original_cache_time)

    def test_concurrent_kev_loads_return_identical_membership(self):
        # The first KEV load fills the process cache; concurrent first loads
        # must all return the same membership set.
        payload = {"vulnerabilities": [{"cveID": FIRST}]}
        client = Mock()
        client.return_value.json.return_value = payload
        client.return_value.raise_for_status.return_value = None
        original_kev = source._kev_cache
        original_kev_time = source._kev_cache_time
        try:
            with patch.object(source.requests, "get", client):
                results = []
                errors = []

                def worker():
                    try:
                        results.append(source.load_cisa_kev())
                    except BaseException as exc:
                        errors.append(exc)

                threads = [threading.Thread(target=worker) for _ in range(8)]
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join(timeout=15)
                self.assertEqual(errors, [])
                self.assertTrue(all(result == {FIRST} for result in results))
        finally:
            source._kev_cache = original_kev
            source._kev_cache_time = original_kev_time


if __name__ == "__main__":
    unittest.main()
