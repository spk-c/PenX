"""Offline regression for bounded Debian security-tracker snapshot reads.

Uses only synthetic JSON in disposable directories. Does not fetch advisories,
read system package data, open a production DB or invoke scanners.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from penx_app.intelligence import vendor_status as vendor


CVE = "CVE-2026-12345"


def tracker():
    return {"openssh": {
        CVE: {"releases": {"bookworm": {
            "status": "not-affected", "fixed_version": "0"
        }}}
    }}


class BoundedDebianSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="penx-debian-snapshot-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / "tracker.json"
        vendor._read_debian_snapshot.cache_clear()
        self.addCleanup(vendor._read_debian_snapshot.cache_clear)

    def read(self):
        return vendor._read_debian_snapshot(
            str(self.path), self.path.lstat().st_mtime_ns
        )

    def test_small_valid_snapshot_and_vendor_guidance_still_work(self):
        self.path.write_text(json.dumps(tracker()), encoding="utf-8")
        self.assertEqual(self.read(), tracker())
        rows = vendor.vendor_guidance(
            {"id": CVE}, distro_hint="debian:bookworm",
            inventory={
                "distro": "debian", "release": "bookworm",
                "packages": {"openssh": "1:9.2p1-2"},
            }, debian_tracker_file=str(self.path),
        )
        self.assertEqual(rows[0]["installed_status"], "vendor-says-not-affected")
        self.assertEqual(rows[0]["fixed_version"], "0")

    def test_oversized_file_is_rejected_before_parsing(self):
        self.path.write_bytes(b" " * 1025)
        with patch.object(vendor, "MAX_DEBIAN_SNAPSHOT_BYTES", 1024), \
             self.assertRaisesRegex(ValueError, "exceeds 30 MB"):
            self.read()

    def test_size_guard_checks_actual_consumed_bytes_after_stale_metadata(self):
        self.path.write_bytes(b"x" * 400)
        original_fstat = os.fstat

        def fake_fstat(fd):
            info = original_fstat(fd)
            class Stale:
                st_dev = info.st_dev
                st_ino = info.st_ino
                st_mode = info.st_mode
                st_size = 1
            return Stale()

        with patch.object(vendor, "MAX_DEBIAN_SNAPSHOT_BYTES", 100), \
             patch.object(vendor.os, "fstat", side_effect=fake_fstat), \
             self.assertRaisesRegex(ValueError, "exceeds 30 MB"):
            self.read()

    def test_symlink_to_valid_snapshot_is_not_trusted(self):
        original = self.root / "original.json"
        original.write_text(json.dumps(tracker()), encoding="utf-8")
        try:
            self.path.symlink_to(original)
        except (OSError, NotImplementedError):
            self.skipTest("Symlinks unavailable on host")
        self.assertIsNone(vendor._debian_tracker_entry(
            CVE, "openssh", "bookworm", str(self.path),
        ))
        self.assertEqual(json.loads(original.read_text()), tracker())

    def test_corrupted_tracker_fails_closed_without_vendor_fix_assertion(self):
        self.path.write_text("{invalid json", encoding="utf-8")
        self.assertIsNone(vendor._debian_tracker_entry(
            CVE, "openssh", "bookworm", str(self.path),
        ))

    def test_reader_handles_replaced_filename_as_new_snapshot(self):
        self.path.write_text(json.dumps(tracker()), encoding="utf-8")
        first = self.read()
        self.assertEqual(first["openssh"][CVE]["releases"]["bookworm"]["fixed_version"], "0")
        replacement = self.root / "replacement.json"
        newdata = {"openssh": {
            CVE: {"releases": {"bookworm": {
                "status": "open", "fixed_version": ""
            }}}
        }}
        replacement.write_text(json.dumps(newdata), encoding="utf-8")
        replacement.replace(self.path)
        self.assertEqual(self.read(), newdata)


if __name__ == "__main__":
    unittest.main()
