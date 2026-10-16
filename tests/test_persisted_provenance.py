"""Adapter provenance survives assessment persistence without trusting model claims.

Only disposable SQLite fixtures; no network, model calls, or real user data.
"""
from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from penx_app.application.assessment_service import AssessmentPorts, run_assessment
from penx_app.domain.evidence import capture_evidence
from penx_app.domain.scan_models import ScanResult, ScannerResult
from penx_app.scanners.scan_results import format_recon_for_llm
from penx_app.storage import db
from penx_app.storage.db_backend import SQLiteConnection
from penx_app.storage.schema_migrations import initialize_sqlite
from penx_app.storage.session_repository import SessionRepository


class PersistedProvenanceContracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="penx-provenance-sqlite-")
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "assessment.sqlite3"

    def connect(self):
        conn = sqlite3.connect(self.path)
        initialize_sqlite(conn)
        return SQLiteConnection(conn)

    def test_saved_assessment_retains_source_bound_anchors_not_model_claims(self):
        text = "80/tcp open http\n"
        scanner = ScannerResult("nmap", text, "COMPLETE", True, "Nmap")
        record = capture_evidence(scanner, 0, len(text),
                                  kind="adapter_output", parser_version=1)
        scanner = ScannerResult("nmap", text, "COMPLETE", True, "Nmap",
                                evidence_records=(record,))
        raw = format_recon_for_llm(ScanResult((scanner,)))
        bogus = json.dumps({"version": 2, "adapters": [{
            "id": "fake", "name": "Fake", "status": "COMPLETE", "evidence": True,
        }]})
        coverage = {"status": "COMPLETE", "note": "fixture", "failed": []}
        calls = []
        ports = AssessmentPorts(
            create_session=db.create_session,
            analyse=lambda target, scan, **kwargs: {
                "risk_level": "LOW", "full_response": "synthetic response",
                "vulnerabilities": [], "recommendations": [], "exploits": [],
                "scan_metadata": bogus,
            },
            save=db.save_assessment,
            discard=lambda *args: self.fail("Unexpected discard"),
            preserve_assessment=lambda *args: self.fail("Unexpected recovery"),
            export=lambda sl: {},
            notify=lambda event, value: calls.append(event),
        )
        with patch.object(db, "get_connection", side_effect=self.connect):
            outcome = run_assessment("example.test", raw, coverage,
                                     passive_only=False, model_name="fixture",
                                     ports=ports)
        self.assertTrue(outcome.completed)
        self.assertIn("saved", calls)
        with closing(self.connect()) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT scan_metadata FROM summary WHERE sl_no=%s",
                           (outcome.session_id,))
            serialized = cursor.fetchone()[0]
        self.assertNotIn('"id": "fake"', serialized)
        self.assertEqual(json.loads(serialized)["version"], 2)
        stored = SessionRepository(self.connect).snapshot(outcome.session_id)
        self.assertIsNotNone(stored.scan_result)
        self.assertEqual(stored.scan_result.evidence_records(), (record,))
        # On reload, missing raw adapter text is never fabricated or
        # represented as independently reverified scanner evidence.
        self.assertFalse(record.matches(stored.scan_result.results[0]))

    def test_legacy_summary_metadata_stays_readable(self):
        with closing(self.connect()) as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO history (target,scan_date,status) "
                           "VALUES (%s,%s,%s)", ("example.test", "2026-10-16", "active"))
            v1 = ScanResult((ScannerResult("nmap", "", "PARTIAL", False, "Nmap"),)).metadata()
            cursor.execute("INSERT INTO summary "
                           "(sl_no,raw_scan,ai_analysis,risk_level,scan_metadata) "
                           "VALUES (%s,%s,%s,%s,%s)",
                           (1, "offline scan", "offline analysis", "UNKNOWN", v1))
            conn.commit()
        stored = SessionRepository(self.connect).snapshot(1)
        self.assertEqual(stored.scan_result.evidence_records(), ())
        self.assertFalse(stored.scan_result.has_evidence)


if __name__ == "__main__":
    unittest.main()
