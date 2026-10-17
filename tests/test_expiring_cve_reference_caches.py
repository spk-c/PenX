"""CVE-source caches cannot retain stale NVD/KEV statuses indefinitely.

Mock time and HTTP, without any external requests or scanner processes.
"""
from __future__ import annotations

import unittest
from unittest.mock import Mock, patch

from penx_app.intelligence import source_verification as verify


CVE = "CVE-2026-12345"
OTHER = "CVE-2026-67890"


def nvd_response(*ids):
    r = Mock()
    r.raise_for_status.return_value = None
    r.json.return_value = {
        "vulnerabilities": [{"cve": {"id": identifier}} for identifier in ids]
    }
    return r


def kev_response(*ids):
    r = Mock()
    r.raise_for_status.return_value = None
    r.json.return_value = {
        "vulnerabilities": [{"cveID": identifier} for identifier in ids]
    }
    return r


class ExpiringReferenceCachesTests(unittest.TestCase):
    def setUp(self):
        self.original_nvd = verify._nvd_cache.copy()
        self.original_times = verify._nvd_cache_time.copy()
        self.old_kev = verify._kev_cache
        self.old_kev_time = verify._kev_cache_time
        verify._nvd_cache.clear()
        verify._nvd_cache_time.clear()
        verify._kev_cache = None
        verify._kev_cache_time = None

        def restore():
            verify._nvd_cache.clear()
            verify._nvd_cache.update(self.original_nvd)
            verify._nvd_cache_time.clear()
            verify._nvd_cache_time.update(self.original_times)
            verify._kev_cache = self.old_kev
            verify._kev_cache_time = self.old_kev_time
        self.addCleanup(restore)

    def test_nvd_cache_is_reused_only_while_fresh(self):
        client = Mock(side_effect=[nvd_response(CVE), nvd_response()])
        with patch.object(verify.requests, "get", side_effect=client), \
             patch.object(verify.time, "monotonic", side_effect=[
                 100.0, 100.0, 101.0,
                 100.0 + verify.SOURCE_CACHE_TTL_SECONDS + 2,
                 100.0 + verify.SOURCE_CACHE_TTL_SECONDS + 2,
             ]):
            self.assertEqual(verify.lookup_nvd(CVE), "listed")
            self.assertEqual(verify.lookup_nvd(CVE.lower()), "listed")
            self.assertEqual(verify.lookup_nvd(CVE), "not-listed")
        self.assertEqual(client.call_count, 2)

    def test_expired_nvd_cache_not_reused_when_refresh_fails(self):
        import requests

        provider = Mock(side_effect=[nvd_response(CVE),
                                     requests.Timeout("offline fixture")])
        with patch.object(verify.requests, "get", side_effect=provider), \
             patch.object(verify.time, "monotonic", side_effect=[
                 10.0, 10.0,
                 10.0 + verify.SOURCE_CACHE_TTL_SECONDS + 10,
             ]):
            self.assertEqual(verify.lookup_nvd(CVE), "listed")
            self.assertEqual(verify.lookup_nvd(CVE), "unavailable")
        self.assertEqual(provider.call_count, 2)

    def test_kev_cache_refreshes_after_ttl(self):
        provider = Mock(side_effect=[kev_response(CVE), kev_response(OTHER)])
        with patch.object(verify.requests, "get", side_effect=provider), \
             patch.object(verify.time, "monotonic", side_effect=[
                 20.0, 20.0, 21.0,
                 20.0 + verify.SOURCE_CACHE_TTL_SECONDS + 5,
                 20.0 + verify.SOURCE_CACHE_TTL_SECONDS + 5,
             ]):
            self.assertEqual(verify.load_cisa_kev(), {CVE})
            self.assertEqual(verify.load_cisa_kev(), {CVE})
            self.assertEqual(verify.load_cisa_kev(), {OTHER})
        self.assertEqual(provider.call_count, 2)

    def test_expired_kev_cache_returns_unknown_when_refresh_unavailable(self):
        import requests

        provider = Mock(side_effect=[kev_response(CVE),
                                     requests.Timeout("offline fixture")])
        with patch.object(verify.requests, "get", side_effect=provider), \
             patch.object(verify.time, "monotonic", side_effect=[
                 20.0, 20.0,
                 20.0 + verify.SOURCE_CACHE_TTL_SECONDS + 20,
             ]):
            self.assertEqual(verify.load_cisa_kev(), {CVE})
            self.assertIsNone(verify.load_cisa_kev())
        self.assertEqual(provider.call_count, 2)

    def test_injected_provider_cannot_mutate_or_reuse_process_cache(self):
        verify._nvd_cache[CVE] = "not-listed"
        verify._nvd_cache_time[CVE] = 1.0
        verify._kev_cache = {OTHER}
        verify._kev_cache_time = 1.0
        self.assertEqual(verify.lookup_nvd(
            CVE, get=Mock(return_value=nvd_response(CVE))
        ), "listed")
        self.assertEqual(verify.load_cisa_kev(
            get=Mock(return_value=kev_response(CVE))
        ), {CVE})
        self.assertEqual(verify._nvd_cache[CVE], "not-listed")
        self.assertEqual(verify._kev_cache, {OTHER})


if __name__ == "__main__":
    unittest.main()
