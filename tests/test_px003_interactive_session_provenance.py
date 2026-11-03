"""PX-003 interactive capture -> DB history -> offline replay (owned fixtures only)."""
from __future__ import annotations

from contextlib import closing, redirect_stdout
from io import StringIO
import json
import os
import hashlib
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

from penx_app.application.assessment_service import AssessmentPorts, run_assessment
from penx_app.application.evidence_verification import verify_session_provenance, main as verify_cli
from penx_app.cli.scanner_menu import interactive_tool_run
from penx_app.domain.scan_models import (
    ReconText, ScanResult, ScannerResult,
)
from penx_app.scanners.process_runner import run_tool
from penx_app.scanners.scan_results import format_recon_for_llm
from penx_app.storage import db
from penx_app.storage.db_backend import SQLiteConnection
from penx_app.storage.schema_migrations import initialize_sqlite
from penx_app.storage.session_repository import SessionRepository


def fixture_adapter(_target, *, cancel_event=None):
    command = [sys.executable, "-c",
               "import sys;sys.stdout.buffer.write(b'80/tcp open http\\r\\n')"]
    return run_tool(command, cancel_event=cancel_event)


class InteractiveSessionProvenanceTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="penx-interactive-proof-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.raw_dir = self.root / "private-raw"
        self.database = self.root / "history.sqlite"
        with closing(sqlite3.connect(self.database)) as conn:
            initialize_sqlite(conn)

    def connect(self):
        return SQLiteConnection(sqlite3.connect(self.database, timeout=5))

    def collect(self, *, directory=True, adapter=fixture_adapter):
        values = ({"PENX_RAW_ARTIFACT_DIR": str(self.raw_dir)}
                  if directory else {"PENX_RAW_ARTIFACT_DIR": ""})
        with patch.dict(os.environ, values), \
             patch("penx_app.cli.cli_navigation.navigation_input",
                   return_value="1"), \
             patch("penx_app.cli.scanner_menu._preflight_summary"), \
             redirect_stdout(StringIO()):
            return interactive_tool_run(
                "example.test", menu={"1": ("Nmap", adapter)},
                formatter=format_recon_for_llm)

    def save(self, raw):
        self.assertIsInstance(raw, ReconText)
        assessment = {
            "risk_level": "LOW", "full_response": "fixture review",
            "vulnerabilities": [], "recommendations": [], "exploits": []
        }
        ports = AssessmentPorts(
            create_session=db.create_session,
            analyse=lambda *a, **k: dict(assessment),
            save=db.save_assessment,
            discard=lambda *a: self.fail("discard unexpected"),
            preserve_assessment=lambda *a: self.fail("backup unexpected"),
            export=lambda *_: {},
        )
        with patch.dict(os.environ, {"PENX_RAW_ARTIFACT_DIR": str(self.raw_dir)}), \
             patch.object(db, "get_connection", side_effect=self.connect):
            outcome = run_assessment(
                "example.test", raw,
                {"status": "COMPLETE", "note": "fixture", "failed": []},
                passive_only=False, model_name="offline-fixture", ports=ports)
        self.assertTrue(outcome.completed, outcome.error)
        return outcome.session_id

    def test_interactive_opt_in_preserves_source_bytes_on_adapter_and_metadata(self):
        raw = self.collect()
        self.assertEqual(len(raw.result.results), 1)
        adapter = raw.result.results[0]
        self.assertIsNotNone(adapter.stdout_capture)
        self.assertEqual(adapter.stdout_capture.validator,
                         "sha256-predecode-stdout-v1")
        sid = self.save(raw)
        snapshot = SessionRepository(self.connect).snapshot(sid)
        self.assertEqual(snapshot.history.session_id, sid)
        self.assertEqual(snapshot.scan_result.results[0].stdout_capture,
                         adapter.stdout_capture)
        self.assertEqual(snapshot.summary.raw_scan, str(raw))
        proof = verify_session_provenance(sid, self.raw_dir, self.connect)
        self.assertEqual(proof["session_id"], sid)
        self.assertTrue(proof["session_raw_text_verified"])
        self.assertEqual(proof["stdout_byte_sources_verified"], 1)
        self.assertEqual(proof["raw_sources_verified"], 1)

    def test_cli_verifies_read_only_disposable_sqlite_without_echoing_scans(self):
        sid = self.save(self.collect())
        stream = StringIO()
        with redirect_stdout(stream):
            status = verify_cli(["--session", str(sid), "--sqlite-db",
                                 str(self.database), "--artifacts", str(self.raw_dir)])
        self.assertEqual(status, 0)
        message = json.loads(stream.getvalue())
        self.assertEqual(message["session_id"], sid)
        self.assertTrue(message["session_raw_text_verified"])
        self.assertNotIn("80/tcp", stream.getvalue())

    def test_default_interactive_scan_does_not_write_binary_capture(self):
        with patch("penx_app.storage.stdout_bytes.publish_unique",
                   side_effect=AssertionError("not opted in")):
            raw = self.collect(directory=False)
        self.assertIsInstance(raw, ReconText)
        self.assertIsNone(raw.result.results[0].stdout_capture)
        self.assertFalse(self.raw_dir.exists())

    def test_tampered_original_bytes_fail_closed(self):
        sid = self.save(self.collect())
        stored = SessionRepository(self.connect).snapshot(sid).scan_result
        rawref = stored.results[0].stdout_capture
        (self.raw_dir / rawref.filename).write_bytes(b"80/tcp open fake\\r\\n")
        with self.assertRaises(ValueError):
            verify_session_provenance(sid, self.raw_dir, self.connect)

    def test_tampered_db_raw_scan_fails_despite_valid_anchors(self):
        sid = self.save(self.collect())
        with closing(sqlite3.connect(self.database)) as conn:
            conn.execute("UPDATE summary SET raw_scan=? WHERE sl_no=?",
                         ("[manipulated text]", sid))
            conn.commit()
        with self.assertRaisesRegex(ValueError, "session"):
            verify_session_provenance(sid, self.raw_dir, self.connect)

    def test_missing_ref_and_historical_session_cannot_be_certified(self):
        sid = self.save(self.collect())
        with closing(sqlite3.connect(self.database)) as conn:
            conn.execute("UPDATE summary SET scan_metadata=? WHERE sl_no=?",
                         (json.dumps({"version":1,"adapters":[
                             {"id":"nmap","name":"Nmap",
                              "status":"COMPLETE","evidence":True}]}), sid))
            conn.commit()
        with self.assertRaises(ValueError):
            verify_session_provenance(sid, self.raw_dir, self.connect)

    def test_missing_or_invalid_readonly_db_fails_without_creating_file(self):
        missing = self.root / "absent.sqlite"
        stream = StringIO()
        with redirect_stdout(stream):
            code = verify_cli(["--session","1","--sqlite-db",str(missing),
                               "--artifacts",str(self.raw_dir)])
        self.assertEqual(code, 2)
        self.assertFalse(missing.exists())
        self.assertEqual(json.loads(stream.getvalue())["status"], "unverified")
        with redirect_stdout(StringIO()):
            code = verify_cli(["--session","0","--sqlite-db",str(self.database),
                               "--artifacts",str(self.raw_dir)])
        self.assertEqual(code,2)

    def test_database_file_unchanged_by_read_only_session_verification(self):
        sid = self.save(self.collect())
        before = hashlib.sha256(self.database.read_bytes()).hexdigest()
        with redirect_stdout(StringIO()) as output:
            code = verify_cli(["--session", str(sid), "--sqlite-db",
                               str(self.database), "--artifacts",
                               str(self.raw_dir)])
        self.assertEqual(code, 0)
        self.assertEqual(hashlib.sha256(
            self.database.read_bytes()).hexdigest(), before)
        self.assertTrue(json.loads(output.getvalue())["session_raw_text_verified"])

    def test_incomplete_second_adapter_prevents_full_session_attestation(self):
        original = self.collect()
        row = original.result.results[0]
        partial = ScannerResult("dns", "Provider unavailable",
                                "PARTIAL", False, "DNS")
        raw = format_recon_for_llm(ScanResult((row, partial)))
        sid = self.save(raw)
        stored = SessionRepository(self.connect).snapshot(sid)
        self.assertEqual(len(stored.scan_result.results), 2)
        with self.assertRaisesRegex(ValueError, "eligible"):
            verify_session_provenance(sid, self.raw_dir, self.connect)

    def test_replaced_session_metadata_and_unknown_session_fail_closed(self):
        sid = self.save(self.collect())
        with self.assertRaises(ValueError):
            verify_session_provenance(sid + 100, self.raw_dir, self.connect)
        with closing(sqlite3.connect(self.database)) as conn:
            metadata = json.loads(
                conn.execute("SELECT scan_metadata FROM summary WHERE sl_no=?",
                             (sid,)).fetchone()[0])
            metadata["adapters"][0]["stdout_capture"]["sha256"] = "0" * 64
            conn.execute("UPDATE summary SET scan_metadata=? WHERE sl_no=?",
                         (json.dumps(metadata), sid))
            conn.commit()
        with self.assertRaises((ValueError, OSError)):
            verify_session_provenance(sid, self.raw_dir, self.connect)

    def test_cross_session_metadata_swap_is_not_certified(self):
        first = self.save(self.collect())
        def alternate_adapter(_target, *, cancel_event=None):
            cmd = [sys.executable, "-c",
                   "import sys;sys.stdout.buffer.write(b'443/tcp open https\\r\\n')"]
            return run_tool(cmd, cancel_event=cancel_event)
        second = self.save(self.collect(adapter=alternate_adapter))
        self.assertNotEqual(first, second)
        with closing(sqlite3.connect(self.database)) as conn:
            other = conn.execute(
                "SELECT scan_metadata FROM summary WHERE sl_no=?",
                (second,)).fetchone()[0]
            conn.execute("UPDATE summary SET scan_metadata=? WHERE sl_no=?",
                         (other, first))
            conn.commit()
        with self.assertRaisesRegex(ValueError,"session"):
            verify_session_provenance(first, self.raw_dir, self.connect)
        self.assertTrue(
            verify_session_provenance(second, self.raw_dir,
                                      self.connect)["session_raw_text_verified"])

    def test_inactive_history_row_is_not_certified(self):
        sid = self.save(self.collect())
        with closing(sqlite3.connect(self.database)) as conn:
            conn.execute("UPDATE history SET status=? WHERE sl_no=?",
                         ("pending", sid))
            conn.commit()
        with self.assertRaises(ValueError):
            verify_session_provenance(sid, self.raw_dir, self.connect)

    def test_session_mode_requires_explicit_database_and_disallows_report(self):
        for argv in (
            ["--session","1","--artifacts",str(self.raw_dir)],
            ["--session","1","--sqlite-db",str(self.database),
             "--report",str(self.root/"a.json"),"--artifacts",str(self.raw_dir)],
            ["--session","1","--metadata",str(self.root/"some.json"),
             "--sqlite-db",str(self.database),"--artifacts",str(self.raw_dir)],
        ):
            with self.subTest(argv=argv),redirect_stdout(StringIO()):
                self.assertEqual(verify_cli(argv),2)


if __name__ == "__main__":
    unittest.main()
