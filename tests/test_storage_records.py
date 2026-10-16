"""Pk06 storage typed records: every session row leaves storage as a named record.

The legacy positional contract must survive: named records are tuples whose
field order matches the explicit public column lists, so existing positional
consumers and tuple-equality assertions keep working unchanged.
"""
from __future__ import annotations

import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from penx_app.storage import db
from penx_app.storage.db_backend import SQLiteConnection
from penx_app.storage.evaluation_repository import (
    load_distillation_package, load_evaluation_package,
)
from penx_app.storage.schema_migrations import initialize_sqlite
from penx_app.storage.session_repository import (
    CorrectionRecord, EvaluationRecord, ExploitRecord, FixRecord,
    Finding, SessionRepository,
)


class StorageRecordContracts(unittest.TestCase):
    def setUp(self):
        self._temp = tempfile.TemporaryDirectory(prefix="penx-storage-records-")
        self.addCleanup(self._temp.cleanup)
        self.db_path = Path(self._temp.name) / "penx.sqlite3"

    def factory(self):
        connection = sqlite3.connect(str(self.db_path))
        initialize_sqlite(connection)
        return SQLiteConnection(connection)

    def seed(self) -> None:
        with closing(self.factory()) as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO history (target, scan_date, status) "
                           "VALUES (%s, %s, %s)", ("example.test", "2026-10-16", "active"))
            cursor.execute("INSERT INTO vulnerabilities "
                           "(sl_no, vuln_name, severity, confidence, port, service, description) "
                           "VALUES (%s, %s, %s, %s, %s, %s, %s)",
                           (1, "Outdated SSH server", "low", "likely", "22", "ssh", "22/tcp open ssh"))
            cursor.execute("INSERT INTO fixes (sl_no, vuln_id, fix_text, source) "
                           "VALUES (%s, %s, %s, %s)", (1, 1, "Restrict access", "ai"))
            cursor.execute("INSERT INTO exploits_attempted "
                           "(sl_no, exploit_name, tool_used, payload, result, notes) "
                           "VALUES (%s, %s, %s, %s, %s, %s)",
                           (1, "Banner probe", "curl", "fixture-payload", "inconclusive", "notes"))
            cursor.execute("INSERT INTO summary "
                           "(sl_no, raw_scan, ai_analysis, risk_level, model_name, generated_at) "
                           "VALUES (%s, %s, %s, %s, %s, %s)",
                           (1, "22/tcp open ssh", "Analysis text", "LOW", "fixture-model", "2026-10-16"))
            cursor.execute("INSERT INTO corrections "
                           "(sl_no, vuln_id, status, original_text, corrected_text, reason, corrected_at) "
                           "VALUES (%s, %s, %s, %s, %s, %s, %s)",
                           (1, 1, "verified", "original", "corrected", "reason", "2026-10-16"))
            cursor.execute("INSERT INTO evaluations "
                           "(sl_no, vuln_id, evaluator, evidence_cited, verdict, confidence, "
                           "severity_correct, cve_correct, software_correct, fix_correct, notes, evaluated_at) "
                           "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                           (1, 1, "human", "22/tcp open ssh", "valid", "high", 1, 0, 1, 1, "ok", "2026-10-16"))
            conn.commit()

    def test_snapshot_returns_named_records(self):
        self.seed()
        snapshot = SessionRepository(self.factory).snapshot(1)
        self.assertIsInstance(snapshot.fixes[0], FixRecord)
        self.assertIsInstance(snapshot.exploits[0], ExploitRecord)
        self.assertIsInstance(snapshot.corrections[0], CorrectionRecord)
        self.assertIsInstance(snapshot.evaluations[0], EvaluationRecord)
        self.assertIsInstance(snapshot.findings[0], Finding)
        self.assertEqual(snapshot.fixes[0].fix_text, "Restrict access")
        self.assertEqual(snapshot.fixes[0].source, "ai")
        self.assertEqual(snapshot.exploits[0].exploit_name, "Banner probe")
        self.assertEqual(snapshot.exploits[0].payload, "fixture-payload")
        self.assertEqual(snapshot.corrections[0].status, "verified")
        self.assertEqual(snapshot.corrections[0].corrected_text, "corrected")
        self.assertEqual(snapshot.evaluations[0].verdict, "valid")
        self.assertEqual(snapshot.evaluations[0].evidence_cited, "22/tcp open ssh")

    def test_legacy_view_keeps_positional_tuple_contract(self):
        self.seed()
        legacy = SessionRepository(self.factory).snapshot(1).as_legacy()
        self.assertEqual(
            legacy["fixes"], [(1, 1, 1, "Restrict access", "ai")])
        self.assertEqual(
            legacy["exploits"],
            [(1, 1, "Banner probe", "curl", "fixture-payload", "inconclusive", "notes")])
        self.assertEqual(
            legacy["corrections"],
            [(1, 1, 1, "verified", "original", "corrected", "reason", "2026-10-16")])
        self.assertEqual(
            legacy["evaluations"],
            [(1, 1, 1, "human", "22/tcp open ssh", "valid", "high",
              1, 0, 1, 1, "ok", "2026-10-16")])
        # Positional consumers (e.g. db_display) keep their indices.
        self.assertEqual(legacy["fixes"][0][3], "Restrict access")
        self.assertEqual(legacy["corrections"][0][3], "verified")
        self.assertEqual(legacy["evaluations"][0][5], "valid")

    def test_named_records_are_plain_tuples(self):
        self.seed()
        snapshot = SessionRepository(self.factory).snapshot(1)
        for record in (
            *snapshot.findings, *snapshot.fixes, *snapshot.exploits,
            *snapshot.corrections, *snapshot.evaluations,
        ):
            self.assertIsInstance(record, tuple)
            self.assertEqual(record, tuple(record))

    def test_evaluation_package_uses_named_records_with_legacy_order(self):
        self.seed()
        payload = load_evaluation_package(1, connection_factory=self.factory)
        self.assertIsInstance(payload["vulns"][0], Finding)
        self.assertIsInstance(payload["fixes"][0], FixRecord)
        self.assertIsInstance(payload["corrections"][0], CorrectionRecord)
        self.assertIsInstance(payload["evaluations"][0], EvaluationRecord)
        # The explicit column lists keep the legacy SELECT * physical order.
        raw = sqlite3.connect(str(self.db_path))
        self.addCleanup(raw.close)
        for key, table in (
            ("vulns", "vulnerabilities"),
            ("fixes", "fixes"),
            ("corrections", "corrections"),
            ("evaluations", "evaluations"),
        ):
            physical = raw.execute(f"SELECT * FROM {table} WHERE sl_no = 1").fetchall()
            self.assertEqual([tuple(row) for row in payload[key]], physical)

    def test_distillation_package_layout_is_unchanged(self):
        self.seed()
        payload = load_distillation_package(connection_factory=self.factory)
        self.assertEqual(payload["corrections"][0],
                         ("verified", "reason", "Outdated SSH server", "low",
                          "example.test", "2026-10-16"))
        self.assertEqual(payload["rules"], [])

    def test_legacy_readers_return_named_records(self):
        self.seed()
        with patch.object(db, "get_connection", self.factory):
            fixes = db.get_fixes(1)
            exploits = db.get_exploits(1)
            corrections = db.get_corrections(1)
        self.assertIsInstance(fixes[0], FixRecord)
        self.assertIsInstance(exploits[0], ExploitRecord)
        self.assertIsInstance(corrections[0], CorrectionRecord)
        # Edit-dialog consumers keep positional access.
        self.assertEqual(fixes[0][3], "Restrict access")
        self.assertEqual(exploits[0][4], "fixture-payload")
        self.assertEqual(corrections[0][3], "verified")


if __name__ == "__main__":
    unittest.main(verbosity=2)
