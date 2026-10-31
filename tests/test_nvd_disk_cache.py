"""Offline regression of the privacy-bounded NVD catalogue cache."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from penx_app.intelligence import cve_engine
from penx_app.intelligence import nvd_disk_cache as cache
from penx_app.intelligence.cve_observations import parse_nmap_services

XML = ('<nmaprun><host><ports><port protocol="tcp" portid="22">'
       '<state state="open"/><service name="ssh" product="OpenSSH" '
       'version="9.2"><cpe>cpe:/a:openbsd:openssh:9.2</cpe></service>'
       '</port></ports></host></nmaprun>')
PRODUCT = parse_nmap_services(XML)[0]


class LocalNvdCacheTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="PenX nvd cache ")
        self.addCleanup(self.temp.cleanup)
        self.env = patch.dict("os.environ", {"PENX_NVD_DISK_CACHE": "1"})
        self.directory = patch.object(cache, "CACHE_DIR", Path(self.temp.name))
        self.env.start()
        self.directory.start()
        self.addCleanup(self.env.stop)
        self.addCleanup(self.directory.stop)
        cve_engine._cached_nvd.cache_clear()
        self.addCleanup(cve_engine._cached_nvd.cache_clear)

    def test_roundtrip_and_expiration(self):
        cpe = PRODUCT.cpe
        rows = ({"cve": {"id": "CVE-2026-12345"}},)
        self.assertTrue(cache.store(cpe, rows, now=100))
        self.assertEqual(cache.load(cpe, now=100 + 3600), rows)
        self.assertEqual(cache.load(cpe, now=100 + cache.TTL_SECONDS + 1), None)
        path = cache.cache_path(cpe)
        self.assertEqual(path.parent, Path(self.temp.name))
        self.assertNotIn("openssh", path.name)
        self.assertEqual(json.loads(path.read_text())["version"], 1)

    def test_empty_result_can_be_cached(self):
        self.assertTrue(cache.store(PRODUCT.cpe, (), now=100))
        self.assertEqual(cache.load(PRODUCT.cpe, now=102), ())

    def test_api_key_never_written_and_no_http_on_cache_hit(self):
        with patch.object(cve_engine, "_get", return_value={
            "totalResults": 1,
            "vulnerabilities": [{"cve": {"id": "CVE-2026-12345"}}],
        }) as web:
            found = cve_engine._cached_nvd(PRODUCT.cpe, "private-nvd-key")
        self.assertEqual(len(found), 1)
        web.assert_called_once()
        self.assertNotIn("private-nvd-key", cache.cache_path(PRODUCT.cpe).read_text())
        cve_engine._cached_nvd.cache_clear()
        with patch.object(cve_engine, "_get", side_effect=AssertionError("must stay offline")):
            cached = cve_engine._cached_nvd(PRODUCT.cpe, "private-nvd-key")
        self.assertEqual(found, cached)

    def test_stale_invalid_large_or_other_cpe_ignored(self):
        cpe = PRODUCT.cpe
        self.assertTrue(cache.store(cpe, ({"cve": {"id": "CVE-2026-12345"}},), now=100))
        path = cache.cache_path(cpe)
        with patch.object(cache.time, "time", return_value=100 + cache.TTL_SECONDS + 2):
            self.assertIsNone(cache.load(cpe))
        path.write_text(json.dumps({"version": 1, "fetched_at": 101,
                                    "key": "wrong", "records": []}))
        self.assertIsNone(cache.load(cpe, now=200))
        path.write_bytes(b"x" * (cache.MAX_CACHE_SIZE + 1))
        self.assertIsNone(cache.load(cpe))

    def test_corrupted_json_fails_closed(self):
        path = cache.cache_path(PRODUCT.cpe)
        path.write_text("{not valid json")
        self.assertIsNone(cache.load(PRODUCT.cpe))

    def test_prune_bounds_total_cache_directory(self):
        unrelated = Path(self.temp.name) / "do-not-remove.json"
        unrelated.write_text("keep", encoding="utf-8")
        with patch.object(cache, "MAX_CACHE_FILES", 3):
            for index in range(9):
                cpe = f"cpe:2.3:a:vendor:product:{index}:*:*:*:*:*:*:*"
                self.assertTrue(cache.store(cpe, ()))
        self.assertEqual(len(list(Path(self.temp.name).glob("*.json"))), 4)
        self.assertEqual(unrelated.read_text(encoding="utf-8"), "keep")

    def test_prune_discards_expired_entry(self):
        cpe = "cpe:2.3:a:vendor:obsolete:1:*:*:*:*:*:*:*"
        self.assertTrue(cache.store(cpe, ()))
        path = cache.cache_path(cpe)
        old = cache.time.time() - cache.TTL_SECONDS - 100
        os.utime(path, (old, old))
        self.assertTrue(cache.store("cpe:2.3:a:vendor:new:1:*:*:*:*:*:*:*", ()))
        self.assertFalse(path.exists())

    def test_disabled_cache_never_writes(self):
        with patch.dict("os.environ", {"PENX_NVD_DISK_CACHE": "0"}):
            self.assertFalse(cache.store(PRODUCT.cpe, ()))
            self.assertIsNone(cache.load(PRODUCT.cpe))
        self.assertEqual(list(Path(self.temp.name).iterdir()), [])

    def test_cache_is_enabled_by_default_when_env_unset(self):
        # The default must stay "on": with no PENX_NVD_DISK_CACHE variable at
        # all, entries are stored and readable.
        env = {key: value for key, value in os.environ.items()
               if key != "PENX_NVD_DISK_CACHE"}
        with patch.dict("os.environ", env, clear=True):
            self.assertTrue(cache.enabled())
            self.assertTrue(cache.store(PRODUCT.cpe, ({"cve": {}},), now=100))
            self.assertEqual(cache.load(PRODUCT.cpe, now=101), ({"cve": {}},))


if __name__ == "__main__":
    unittest.main(verbosity=2)
