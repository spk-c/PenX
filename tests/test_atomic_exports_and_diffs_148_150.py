"""No-overwrite file exports and deterministic duplicate findings (#148-150)."""
from __future__ import annotations

import json
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from penx_app.file_output import publish_unique, replace_config
from penx_app.application import risk_assessment, scan_trends


ROW1 = (11, 1, "Example finding", "high", "confirmed", "443", "https", "fixture")
ROW2 = (12, 1, "Other finding", "low", "possible", "80", "http", "fixture")


class AtomicFileOutputTests(unittest.TestCase):
    def test_unique_exclusive_files_do_not_overwrite_existing_or_symlink(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            foreign = root / "private.txt"
            foreign.write_text("do not touch", encoding="utf-8")
            base = root / "risk_SL1.json"
            try:
                base.symlink_to(foreign)
            except (NotImplementedError, OSError):
                base.write_text("existing", encoding="utf-8")
            first = publish_unique(root, "risk_SL1", ".json", '{"item":1}')
            second = publish_unique(root, "risk_SL1", ".json", '{"item":2}')
            self.assertNotEqual(first, second)
            self.assertNotEqual(first, base)
            self.assertEqual(foreign.read_text(encoding="utf-8"), "do not touch")
            self.assertEqual(first.read_text(encoding="utf-8"), '{"item":1}')
            self.assertEqual(second.read_text(encoding="utf-8"), '{"item":2}')

    def test_atomic_replace_rejects_unsafe_target_and_temp_path(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            path = root / "overrides.json"
            old_fixed_temp = root / "overrides.tmp"
            old_fixed_temp.write_text("old sentinel", encoding="utf-8")
            replace_config(path, '{"old":1}')
            replace_config(path, '{"new":2}')
            self.assertEqual(path.read_text(encoding="utf-8"), '{"new":2}')
            self.assertEqual(old_fixed_temp.read_text(encoding="utf-8"), "old sentinel")
            target = root / "other.json"
            target.write_text("keep", encoding="utf-8")
            path.unlink()
            try:
                path.symlink_to(target)
            except (NotImplementedError, OSError):
                self.skipTest("Symlinks unavailable")
            with self.assertRaises(OSError):
                replace_config(path, '{"attack":1}')
            self.assertEqual(target.read_text(encoding="utf-8"), "keep")

    def test_risk_override_concurrent_threads_preserve_both_findings(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "risk_overrides.json"
            data = {"history": (1, "example.test", "today", "active"),
                    "vulns": [ROW1, ROW2]}
            errors = []
            def update(fid, score):
                try:
                    risk_assessment.save_override(1, fid, score=score, path=path)
                except Exception as exc:
                    errors.append(exc)
            with patch.object(risk_assessment, "get_session", return_value=data):
                threads = [threading.Thread(target=update, args=(11, 88)),
                           threading.Thread(target=update, args=(12, 19))]
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join()
            self.assertEqual(errors, [])
            saved = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(saved["1:11"]["score"], 88)
            self.assertEqual(saved["1:12"]["score"], 19)

    def test_scan_diff_duplicate_order_is_deterministic(self):
        a = (11, 1, "Duplicate finding", "high", "confirmed", "443", "https", "fixture")
        b = (12, 1, "Duplicate finding", "low", "possible", "443", "https", "fixture")
        old = {"history": (1, "example.test", "today", "active"),
               "vulns": [a, b], "summary": None}
        newer = {"history": (2, "example.test", "tomorrow", "active"),
                 "vulns": [(13, 2, *b[2:]), (14, 2, *a[2:])], "summary": None}
        first = scan_trends.compare_sessions(old, newer)
        old["vulns"].reverse()
        newer["vulns"].reverse()
        second = scan_trends.compare_sessions(old, newer)
        self.assertEqual(first, second)
        self.assertEqual(len(first["severity_changes"]), 0)

    def test_json_diff_and_risk_export_keep_old_outputs(self):
        with tempfile.TemporaryDirectory() as folder:
            diff = {"target": "example.test", "from_session": 1,
                    "to_session": 2, "note": "fixture"}
            first = scan_trends.save_diff(diff, folder)
            second = scan_trends.save_diff(diff, folder)
            self.assertNotEqual(first, second)
            self.assertEqual(json.loads(first.read_text(encoding="utf-8")), diff)
            record = {"history": (1, "example.test", "today", "active"), "vulns": [ROW1]}
            with patch.object(risk_assessment, "get_session", return_value=record):
                risk1 = risk_assessment.risk_report_json(1, folder)
                risk2 = risk_assessment.risk_report_json(1, folder)
            self.assertNotEqual(risk1, risk2)
            self.assertTrue(risk1.is_file())
            self.assertTrue(risk2.is_file())


if __name__ == "__main__":
    unittest.main()
