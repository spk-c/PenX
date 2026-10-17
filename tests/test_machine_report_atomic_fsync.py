"""Crash-safe JSON/SARIF exports: complete, synced, exclusive publications.

All fixtures are local synthetic sessions; no database or network access.
"""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from penx_app.reporting.machine_reports import write_machine_report


def fixture():
    return {
        "history": (13, "example.test", "2026-10-17", "active"),
        "summary": (1, 13, "[ NMAP OUTPUT ]\n80/tcp open http",
                    "Synthetic result", "LOW"),
        "vulns": [], "fixes": [], "corrections": [],
    }


class AtomicMachineExportTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="penx-machine-atomic-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)

    def test_exports_keep_complete_json_and_sarif_and_never_overwrite(self):
        for kind in ("json", "sarif"):
            with self.subTest(kind=kind):
                first = write_machine_report(fixture(), self.root, fmt=kind)
                first.write_text("existing report", encoding="utf-8")
                second = write_machine_report(fixture(), self.root, fmt=kind)
                self.assertNotEqual(first, second)
                self.assertEqual(first.read_text(encoding="utf-8"), "existing report")
                saved = json.loads(second.read_text(encoding="utf-8"))
                self.assertEqual(saved["session"] if kind == "json" else saved["runs"][0]["tool"]["driver"]["name"],
                                 13 if kind == "json" else "PenX")
        self.assertFalse([p for p in self.root.iterdir() if p.name.startswith(".penx-stage-")])

    def test_redacted_suffix_is_preserved(self):
        path = write_machine_report(fixture(), self.root, fmt="json", redact=True)
        self.assertEqual(path.name, "penx_SL13_redacted_assessment.json")
        self.assertNotIn("example.test", path.read_text(encoding="utf-8"))

    def test_staged_bytes_are_synced_before_creating_final_name(self):
        import penx_app.file_output as file_output
        original_fsync = file_output.os.fsync
        called = []
        def wrapped(fd):
            called.append("fsync")
            return original_fsync(fd)
        with patch.object(file_output.os, "fsync", side_effect=wrapped):
            saved = write_machine_report(fixture(), self.root, fmt="json")
        self.assertTrue(saved.exists())
        self.assertEqual(called, ["fsync"])

    def test_publishing_error_does_not_leave_partial_named_report(self):
        import penx_app.file_output as file_output
        with patch.object(file_output.os, "link", side_effect=OSError("disk fixture")):
            with self.assertRaises(OSError):
                write_machine_report(fixture(), self.root, fmt="sarif")
        self.assertEqual(list(self.root.iterdir()), [])

    def test_utf8_encoding_error_does_not_leave_partial_report(self):
        data = fixture()
        summary = list(data["summary"])
        summary[3] = "Broken surrogate: \ud800"
        data["summary"] = tuple(summary)
        # JSON serialization escapes lone surrogates because the machine
        # report uses json.dumps(ensure_ascii=False). _stage must clean up
        # failed UTF-8 encoding attempts.
        # A report might omit summary text, so force the target instead.
        history = list(data["history"])
        history[1] = "bad\ud800"
        data["history"] = tuple(history)
        with self.assertRaises(UnicodeEncodeError):
            write_machine_report(data, self.root, fmt="json")
        self.assertEqual(list(self.root.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
