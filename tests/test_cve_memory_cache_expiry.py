"""Expiry and ownership contracts for in-memory public CVE catalogues.

Mocks replace source transports and monotonic time. No live HTTP/scanning.
"""
from __future__ import annotations

import unittest
from unittest.mock import Mock, patch

from penx_app.intelligence import cve_engine as engine
from penx_app.intelligence import nvd_disk_cache
from penx_app.intelligence import source_verification as verify

CPE = "cpe:2.3:a:openbsd:openssh:9.2:*:*:*:*:*:*:*"
CVE = "CVE-2026-12345"
OTHER = "CVE-2026-67890"


def kev_response(*ids):
    response = Mock()
    response.raise_for_status.return_value = None
    response.json.return_value = {
        "vulnerabilities": [{"cveID": identifier} for identifier in ids]
    }
    return response


class MemoryNvdExpiryTests(unittest.TestCase):
    def setUp(self):
        engine._cached_nvd.cache_clear()
        self.addCleanup(engine._cached_nvd.cache_clear)
        disabled = patch.object(nvd_disk_cache, "enabled", return_value=False)
        disabled.start()
        self.addCleanup(disabled.stop)

    def test_same_window_reuses_only_one_source_response(self):
        fetched = Mock(return_value=({"cve": {"id": CVE}},))
        with patch.object(engine, "_fetch_nvd", fetched), \
             patch.object(engine.time, "monotonic", return_value=100.0):
            first = engine._cached_nvd(CPE, "fixture-key")
            second = engine._cached_nvd(CPE, "fixture-key")
        self.assertEqual(first, second)
        fetched.assert_called_once_with(CPE, "fixture-key")

    def test_new_window_reloads_upstream_after_expiry(self):
        old = ({"cve": {"id": CVE}},)
        new = ({"cve": {"id": OTHER}},)
        fetched = Mock(side_effect=[old, new])
        with patch.object(engine, "_fetch_nvd", fetched), \
             patch.object(engine.time, "monotonic",
                          side_effect=[100.0,
                                       engine.NVD_MEMORY_TTL_SECONDS + 101.0]):
            self.assertEqual(engine._cached_nvd(CPE, ""), old)
            self.assertEqual(engine._cached_nvd(CPE, ""), new)
        self.assertEqual(fetched.call_count, 2)

    def test_cache_reset_api_still_forces_fetch(self):
        fetched = Mock(side_effect=[({"cve": {"id": CVE}},),
                                    ({"cve": {"id": OTHER}},)])
        with patch.object(engine, "_fetch_nvd", fetched), \
             patch.object(engine.time, "monotonic", return_value=500.0):
            first = engine._cached_nvd(CPE, "")
            engine._cached_nvd.cache_clear()
            second = engine._cached_nvd(CPE, "")
        self.assertNotEqual(first, second)
        self.assertEqual(fetched.call_count, 2)

    def test_api_keys_still_use_distinct_memory_entries(self):
        fetched = Mock(side_effect=[
            ({"cve": {"id": CVE}},), ({"cve": {"id": OTHER}},),
        ])
        with patch.object(engine, "_fetch_nvd", fetched), \
             patch.object(engine.time, "monotonic", return_value=100.0):
            first = engine._cached_nvd(CPE, "key-1")
            second = engine._cached_nvd(CPE, "key-2")
        self.assertNotEqual(first, second)
        self.assertEqual(fetched.call_count, 2)

    def test_expired_cached_value_not_returned_when_refresh_fails(self):
        import requests

        fetched = Mock(side_effect=[
            ({"cve": {"id": CVE}},),
            requests.Timeout("synthetic offline failure"),
        ])
        with patch.object(engine, "_fetch_nvd", fetched), \
             patch.object(engine.time, "monotonic",
                          side_effect=[100.0,
                                       engine.NVD_MEMORY_TTL_SECONDS + 101.0]):
            self.assertEqual(engine._cached_nvd(CPE, "")[0]["cve"]["id"], CVE)
            with self.assertRaises(requests.Timeout):
                engine._cached_nvd(CPE, "")
        self.assertEqual(fetched.call_count, 2)


class KevCacheOwnershipTests(unittest.TestCase):
    def setUp(self):
        self.older_set = verify._kev_cache
        self.older_time = verify._kev_cache_time
        verify._kev_cache = None
        verify._kev_cache_time = None
        self.addCleanup(self.restore)

    def restore(self):
        verify._kev_cache = self.older_set
        verify._kev_cache_time = self.older_time

    def test_first_return_and_cache_hit_cannot_mutate_cached_membership(self):
        client = Mock(return_value=kev_response(CVE))
        with patch.object(verify.requests, "get", client), \
             patch.object(verify.time, "monotonic", return_value=100.0):
            original = verify.load_cisa_kev()
            self.assertEqual(original, {CVE})
            original.clear()
            second = verify.load_cisa_kev()
            self.assertEqual(second, {CVE})
            second.add(OTHER)
            third = verify.load_cisa_kev()
            self.assertEqual(third, {CVE})
        client.assert_called_once()
        self.assertEqual(verify._kev_cache, {CVE})

    def test_injected_source_remains_call_scoped(self):
        with patch.object(verify.requests, "get",
                          side_effect=AssertionError("must stay offline")):
            payload = kev_response(OTHER)
            self.assertEqual(verify.load_cisa_kev(get=lambda *_a, **_k: payload),
                             {OTHER})
        self.assertIsNone(verify._kev_cache)


if __name__ == "__main__":
    unittest.main()
