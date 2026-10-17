"""Audit regressions for disk-cache and inventory TOCTOU/bounds contracts.

All files are synthetic and isolated to TemporaryDirectory; no API requests.
"""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from penx_app.intelligence import nvd_disk_cache as cache
from penx_app.intelligence import package_inventory as inventory


CPE = "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"


class BoundedDiskReadAuditTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        env = patch.dict("os.environ", {"PENX_NVD_DISK_CACHE": "1"})
        env.start()
        self.addCleanup(env.stop)
        cache_dir = patch.object(cache, "CACHE_DIR", self.root)
        cache_dir.start()
        self.addCleanup(cache_dir.stop)

    def test_nvd_roundtrip_uses_same_open_file_and_rejects_symlink(self):
        original = ({"cve": {"id": "CVE-2026-12345"}},)
        self.assertTrue(cache.store(CPE, original, now=123.0))
        self.assertEqual(cache.load(CPE, now=123.0), original)
        original_path = cache.cache_path(CPE)
        linked = self.root / "linked-cache.json"
        try:
            original_path.rename(linked)
            original_path.symlink_to(linked)
        except (OSError, NotImplementedError):
            self.skipTest("Symlinks not supported")
        self.assertIsNone(cache.load(CPE, now=123.0))
        self.assertEqual(json.loads(linked.read_text())["version"], 1)

    def test_nvd_read_is_bounded_even_when_stat_reports_stale_small_size(self):
        self.assertTrue(cache.store(CPE, (), now=10.0))
        file_path = cache.cache_path(CPE)
        file_path.write_bytes(b"x" * 1500)
        actual_fstat = cache.os.fstat

        class PretendSmall:
            def __init__(self, info):
                self.st_mode = info.st_mode
                self.st_dev = info.st_dev
                self.st_ino = info.st_ino
                self.st_size = 1

        with patch.object(cache, "MAX_CACHE_SIZE", 200), \
             patch.object(cache.os, "fstat",
                          side_effect=lambda fd: PretendSmall(actual_fstat(fd))):
            self.assertIsNone(cache.load(CPE, now=10.0))

    def test_nvd_store_malformed_values_fail_without_creating_files(self):
        for bad in (None, "not records", {"cve": 1},
                    ({"cve": {"id": object()}},),
                    ({"score": float("nan")},)):
            with self.subTest(value=repr(bad)):
                self.assertFalse(cache.store(CPE, bad))
        self.assertEqual(list(self.root.iterdir()), [])

    def test_inventory_accepts_valid_small_json(self):
        path = self.root / "inventory.json"
        path.write_text(json.dumps({
            "distro": "ubuntu", "release": "24.04",
            "packages": [{"source": "openssh", "version": "1:9.6p1-3ubuntu13"}],
        }), encoding="utf-8")
        result = inventory.load_inventory(str(path))
        self.assertEqual(result["packages"]["openssh"], "1:9.6p1-3ubuntu13")

    def test_inventory_rejects_symlink_to_other_file(self):
        path = self.root / "inventory.json"
        foreign = self.root / "outside.json"
        foreign.write_text('{"packages":[]}', encoding="utf-8")
        try:
            path.symlink_to(foreign)
        except (OSError, NotImplementedError):
            self.skipTest("Symlinks not supported")
        with self.assertRaises((OSError, inventory.InventoryError)):
            inventory.load_inventory(str(path))

    def test_inventory_read_rechecks_actual_byte_count_not_stale_stat(self):
        path = self.root / "inventory.json"
        path.write_bytes(b" " * 8192)
        real_fstat = inventory.os.fstat

        class PretendSmall:
            def __init__(self, obj):
                self.st_mode = obj.st_mode
                self.st_dev = obj.st_dev
                self.st_ino = obj.st_ino
                self.st_size = 1

        with patch.object(inventory, "MAX_INVENTORY_BYTES", 1024), \
             patch.object(inventory.os, "fstat",
                          side_effect=lambda fd: PretendSmall(real_fstat(fd))):
            with self.assertRaisesRegex(inventory.InventoryError, "exceeds"):
                inventory.load_inventory(str(path))

    def test_inventory_oversize_files_and_invalid_shape_fail_closed(self):
        path = self.root / "inventory.json"
        path.write_bytes(b" " * (inventory.MAX_INVENTORY_BYTES + 1))
        with self.assertRaisesRegex(inventory.InventoryError, "exceeds"):
            inventory.load_inventory(str(path))
        path.write_text('{"packages":{}}', encoding="utf-8")
        with self.assertRaises(inventory.InventoryError):
            inventory.load_inventory(str(path))


if __name__ == "__main__":
    unittest.main()
