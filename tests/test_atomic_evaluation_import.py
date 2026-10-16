"""Atomic evaluation import contracts with isolated, synthetic SQLite data."""
from __future__ import annotations

import sqlite3
from contextlib import closing
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from penx_app.storage import db_evals
from penx_app.storage.db_backend import SQLiteConnection
from penx_app.storage.schema_migrations import initialize_sqlite


REVIEW = (
    "EVAL: First observation\n"
    "VERDICT: hallucination\n"
    "EVIDENCE: No matching scanner evidence\n"
    "SEVERITY_CORRECT: no\nCVE_CORRECT: no\n"
    "SOFTWARE_CORRECT: no\nFIX_CORRECT: no\n"
    "NOTES: Unsupported finding\n"
    "EVAL: Second observation\n"
    "VERDICT: valid\n"
    "CONFIDENCE: high\n"
    "SEVERITY_CORRECT: yes\nCVE_CORRECT: yes\n"
    "SOFTWARE_CORRECT: yes\nFIX_CORRECT: yes\n"
)


class AtomicEvaluationImportTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(prefix="penx-atomic-evals-")
        self.addCleanup(self.folder.cleanup)
        self.db_path = Path(self.folder.name) / "fixture.sqlite"
        with closing(sqlite3.connect(self.db_path)) as conn:
            initialize_sqlite(conn)
            conn.execute(
                "INSERT INTO history (sl_no, target, scan_date, status) "
                "VALUES (1, 'example.test', '2026-10-15', 'active')"
            )
            conn.execute(
                "INSERT INTO history (sl_no, target, scan_date, status) "
                "VALUES (2, 'unrelated.test', '2026-10-15', 'active')"
            )
            conn.executemany(
                "INSERT INTO vulnerabilities "
                "(id, sl_no, vuln_name, severity, confidence, port, service, description) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    (11, 1, "First observation", "low", "possible", "80", "http", "fixture"),
                    (12, 1, "Second observation", "low", "possible", "443", "https", "fixture"),
                    (13, 2, "First observation", "low", "possible", "80", "http", "other"),
                ],
            )
            conn.commit()

    def factory(self):
        return SQLiteConnection(sqlite3.connect(self.db_path))

    def counts(self):
        with closing(sqlite3.connect(self.db_path)) as conn:
            return (
                conn.execute("SELECT COUNT(*) FROM evaluations").fetchone()[0],
                conn.execute("SELECT COUNT(*) FROM corrections").fetchone()[0],
            )

    def test_all_evaluations_and_auto_corrections_commit_together(self):
        with patch.object(db_evals, "get_connection", side_effect=self.factory):
            saved_ids = db_evals.parse_evaluation_response(1, "fixture-reviewer", REVIEW)
        self.assertEqual(len(saved_ids), 2)
        self.assertEqual(self.counts(), (2, 1))
        with closing(sqlite3.connect(self.db_path)) as conn:
            self.assertEqual(
                conn.execute("SELECT DISTINCT sl_no FROM evaluations").fetchall(), [(1,)]
            )
            self.assertEqual(
                conn.execute("SELECT vuln_id FROM corrections").fetchall(), [(11,)]
            )

    def test_later_evaluation_insert_failure_rolls_back_first_and_its_correction(self):
        with closing(sqlite3.connect(self.db_path)) as conn:
            conn.executescript(
                "CREATE TRIGGER block_second_eval BEFORE INSERT ON evaluations "
                "WHEN NEW.vuln_id = 12 "
                "BEGIN SELECT RAISE(ABORT, 'synthetic insert rejection'); END;"
            )
        with patch.object(db_evals, "get_connection", side_effect=self.factory):
            with self.assertRaisesRegex(sqlite3.Error, "synthetic insert rejection"):
                db_evals.parse_evaluation_response(1, "fixture-reviewer", REVIEW)
        self.assertEqual(self.counts(), (0, 0))

    def test_correction_insert_failure_rolls_back_earlier_evaluation(self):
        with closing(sqlite3.connect(self.db_path)) as conn:
            conn.executescript(
                "CREATE TRIGGER block_correction BEFORE INSERT ON corrections "
                "BEGIN SELECT RAISE(ABORT, 'synthetic correction rejection'); END;"
            )
        with patch.object(db_evals, "get_connection", side_effect=self.factory):
            with self.assertRaisesRegex(sqlite3.Error, "synthetic correction rejection"):
                db_evals.parse_evaluation_response(1, "fixture-reviewer", REVIEW)
        self.assertEqual(self.counts(), (0, 0))

    def test_ambiguous_names_and_invalid_verdicts_do_not_write(self):
        text = (
            "EVAL: Not in this session\nVERDICT: hallucination\n"
            "EVAL: First observation\nVERDICT: nonsense\n"
        )
        with patch.object(db_evals, "get_connection", side_effect=self.factory):
            self.assertEqual(db_evals.parse_evaluation_response(1, "fixture", text), [])
        self.assertEqual(self.counts(), (0, 0))


if __name__ == "__main__":
    unittest.main()
