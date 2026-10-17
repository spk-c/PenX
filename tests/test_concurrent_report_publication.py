"""Concurrent report writers must not corrupt a session's publication state.

Pure temporary fixtures; uses actual threads and subprocess file locks so this
works as a regression test on both GitHub windows-latest and ubuntu-latest.
"""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from penx_app.reporting import report_batch, report_management


class ReportPublicationLockContracts(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="penx-concurrent-reports-")
        self.addCleanup(self.tmp.cleanup)
        self.folder = Path(self.tmp.name)
        self.data = {
            "history": (7, "fixture.test", "today", "active"),
            "summary": (1, 7, "raw", "analysis", "LOW", "local", "today"),
            "vulns": [], "fixes": [], "corrections": [],
        }
        self.targets = report_management.report_paths(7, "fixture.test", self.folder)

    @staticmethod
    def render(text, started=None, release=None):
        def renderer(data, staging):
            if started is not None:
                started.set()
                if not release.wait(8):
                    raise TimeoutError("fixture renderer was not released")
            output = Path(staging) / "rendered.html"
            output.write_text(text, encoding="utf-8")
            return output
        return renderer

    def start_two(self, first, second, first_started, second_started, release):
        outcomes = []
        errors = []

        def run(fn):
            try:
                outcomes.append(fn())
            except BaseException as exc:
                errors.append(exc)

        a = threading.Thread(target=run, args=(first,), daemon=True)
        b = threading.Thread(target=run, args=(second,), daemon=True)
        a.start()
        try:
            self.assertTrue(first_started.wait(4), "First renderer did not start")
            b.start()
            # A second renderer may not run until the first has finalized
            # its manifest and released the per-session file lock.
            self.assertFalse(second_started.wait(0.35),
                             "Two exports ran concurrently for the same session")
        finally:
            release.set()
            a.join(8)
            if b.ident is not None:
                b.join(8)
        self.assertFalse(a.is_alive())
        self.assertFalse(b.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(len(outcomes), 2)

    def test_two_independent_exports_are_serialized(self):
        started = threading.Event()
        second_started = threading.Event()
        release = threading.Event()

        def first():
            return report_batch.publish_reports(
                self.data, self.folder, self.targets, formats=("html",),
                html_export=self.render("first", started, release),
                pdf_export=lambda *_: None,
                machine_export=lambda *_args, **_kwargs: None,
            )

        def second():
            return report_batch.publish_reports(
                self.data, self.folder, self.targets, formats=("html",),
                html_export=self.render("second", second_started),
                pdf_export=lambda *_: None,
                machine_export=lambda *_args, **_kwargs: None,
            )

        self.start_two(first, second, started, second_started, release)
        self.assertEqual(self.targets["html"].read_text(encoding="utf-8"), "second")
        state = report_batch.publication_state(self.folder, 7)
        self.assertEqual(state["status"], "complete")
        self.assertEqual(state["formats"], ["html"])

    def test_atomic_pair_and_independent_export_do_not_overlap(self):
        started = threading.Event()
        second_started = threading.Event()
        release = threading.Event()
        def pair_html(_data, staging):
            started.set()
            if not release.wait(8):
                raise TimeoutError("fixture renderer was not released")
            result = Path(staging) / "pair.html"
            result.write_text("pair html", encoding="utf-8")
            return str(result)
        def pair_pdf(_data, staging):
            result = Path(staging) / "pair.pdf"
            result.write_text("pair pdf", encoding="utf-8")
            return str(result)

        def first():
            return report_management.generate_session_reports(7, directory=self.folder)

        def second():
            return report_batch.publish_reports(
                self.data, self.folder, self.targets, formats=("html",),
                html_export=self.render("independent", second_started),
                pdf_export=lambda *_: None,
                machine_export=lambda *_args, **_kw: None,
            )

        with patch.object(report_management, "get_session", return_value=self.data), \
             patch.object(report_management, "add_saved_comparison",
                          side_effect=lambda d: d), \
             patch.object(report_management, "export_html", side_effect=pair_html), \
             patch.object(report_management, "export_pdf", side_effect=pair_pdf):
            self.start_two(first, second, started, second_started, release)

        self.assertEqual(self.targets["html"].read_text(encoding="utf-8"),
                         "independent")
        self.assertEqual(self.targets["pdf"].read_text(encoding="utf-8"),
                         "pair pdf")
        self.assertEqual(report_batch.publication_state(self.folder, 7)["status"],
                         "complete")

    def test_delete_waits_for_in_flight_publication(self):
        started = threading.Event()
        deleted = threading.Event()
        release = threading.Event()

        def first():
            return report_batch.publish_reports(
                self.data, self.folder, self.targets, formats=("html",),
                html_export=self.render("temporary", started, release),
                pdf_export=lambda *_: None,
                machine_export=lambda *_args, **_kw: None,
            )

        def second():
            removed = report_management.delete_session_reports(
                7, "fixture.test", directory=self.folder)
            deleted.set()
            return removed

        self.start_two(first, second, started, deleted, release)
        self.assertFalse(self.targets["html"].exists())
        self.assertIsNone(report_batch.publication_state(self.folder, 7))
        # Lock files must be retained; deleting while held could create two
        # independent file inodes and defeat interprocess serialization.
        self.assertTrue((self.folder / ".penx-publication_SL7.lock").is_file())

    def test_lock_timeout_releases_after_failure_and_different_session_works(self):
        started = threading.Event()
        release = threading.Event()
        def first():
            with report_batch.publication_lock(self.folder, 7):
                started.set()
                self.assertTrue(release.wait(8))
        worker = threading.Thread(target=first, daemon=True)
        worker.start()
        try:
            self.assertTrue(started.wait(4))
            with self.assertRaises(TimeoutError):
                with report_batch.publication_lock(self.folder, 7, timeout=0.1):
                    self.fail("Second writer obtained an already-held lock")
            with report_batch.publication_lock(self.folder, 8, timeout=0.1):
                pass
        finally:
            release.set()
            worker.join(8)
        self.assertFalse(worker.is_alive())
        with report_batch.publication_lock(self.folder, 7, timeout=0.1):
            pass
        with self.assertRaisesRegex(RuntimeError, "fixture crash"):
            with report_batch.publication_lock(self.folder, 7):
                raise RuntimeError("fixture crash")
        with report_batch.publication_lock(self.folder, 7, timeout=0.1):
            pass

    def test_subprocess_lock_is_released_after_termination(self):
        child = (
            "import pathlib,sys,time\n"
            "from penx_app.reporting.report_batch import publication_lock\n"
            "with publication_lock(pathlib.Path(sys.argv[1]), 7):\n"
            " print('locked', flush=True)\n"
            " time.sleep(15)\n"
        )
        env = dict(os.environ)
        root = Path(__file__).resolve().parents[1] / "src"
        env["PYTHONPATH"] = str(root) + os.pathsep + env.get("PYTHONPATH", "")
        proc = subprocess.Popen(
            [sys.executable, "-c", child, str(self.folder)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env,
        )
        try:
            ready = proc.stdout.readline().strip()
            if ready != "locked":
                raise AssertionError("Child failed to lock: " + proc.stderr.read())
            with self.assertRaises(TimeoutError):
                with report_batch.publication_lock(self.folder, 7, timeout=0.15):
                    pass
        finally:
            proc.terminate()
            proc.communicate(timeout=8)
        with report_batch.publication_lock(self.folder, 7, timeout=1.0):
            pass


if __name__ == "__main__":
    unittest.main()
