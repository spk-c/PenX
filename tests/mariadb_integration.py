"""Live MariaDB schema and CRUD regressions (NOT part of offline_tests.py).

Run only against disposable, dedicated local/CI databases with
PENX_MARIADB_TEST=1 and a database name ending in _test.
"""
from __future__ import annotations

import os
from pathlib import Path
import unittest

from penx_app.storage import db
from penx_app.storage import db_backend
from penx_app.storage import db_evals
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]


class MariaDBIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if (os.getenv("PENX_MARIADB_TEST") != "1" or
                db_backend.DB_ENGINE != "mariadb" or
                db_backend.DB_HOST not in {"127.0.0.1", "localhost", "::1"} or
                not db_backend.DB_NAME.endswith("_test")):
            raise RuntimeError(
                "Refusing MariaDB integration tests without PENX_MARIADB_TEST=1, "
                "PENX_DB_ENGINE=mariadb, a loopback server and a *_test database."
            )
        # The test DB is disposable. Apply ALL public migration files in order,
        # not a separately maintained test-only approximation of the schema.
        conn = db_backend.get_connection()
        try:
            cursor = conn.cursor()
            for path in sorted((ROOT / "migrations").glob("[0-9][0-9][0-9]_*.sql")):
                sql = "\n".join(
                    line for line in path.read_text(encoding="utf-8").splitlines()
                    if not line.lstrip().startswith("--")
                )
                for statement in sql.split(";"):
                    if statement.strip():
                        cursor.execute(statement.strip())
                        if cursor.with_rows:
                            cursor.fetchall()
            conn.commit()
        finally:
            conn.close()

    def setUp(self):
        self.sl = db.create_session("ci.example.test", status="pending")

    def tearDown(self):
        db.delete_full_session(self.sl)

    def test_assessment_migrated_schema_and_scoped_edits(self):
        # A pending assessment must not be visible as a completed scan.
        self.assertNotIn(self.sl, [row[0] for row in db.get_all_history()])
        counts = db.save_assessment(self.sl, {
            "risk_level": "LOW",
            "raw_scan": "[ NMAP OUTPUT ]\n80/tcp open http",
            "full_response": "Fixture evidence only",
            "vulnerabilities": [{
                "vuln_name": "Observed open port", "severity": "low",
                "confidence": "possible", "port": "80", "service": "http",
                "description": "Visible service (not a proven vulnerability)",
                "fix": "Review exposure",
            }],
            "exploits": [],
        }, model_name="integration-fixture")
        self.assertEqual(counts["vulnerabilities"], 1)
        self.assertIn(self.sl, [row[0] for row in db.get_all_history()])
        data = db.get_session(self.sl)
        self.assertEqual(data["summary"][5], "integration-fixture")
        vuln = data["vulns"][0]
        self.assertEqual(vuln[4], "possible")  # Stable migrated tuple layout.
        self.assertEqual(vuln[5:7], ("80", "http"))
        self.assertTrue(db.edit_vulnerability(vuln[0], "description", "Revised", sl_no=self.sl))
        self.assertFalse(db.edit_vulnerability(vuln[0], "description", "Wrong session",
                                               sl_no=self.sl + 9999))
        self.assertTrue(db.edit_summary_risk(self.sl, "HIGH"))
        self.assertFalse(db.edit_summary_risk(self.sl + 9999, "HIGH"))
        self.assertEqual(db.get_session(self.sl)["summary"][4], "HIGH")
        # Dependent fix must be removed when deleting a vulnerability.
        self.assertEqual(len(db.get_session(self.sl)["fixes"]), 1)
        self.assertTrue(db.delete_vulnerability(vuln[0], sl_no=self.sl))
        self.assertEqual(db.get_session(self.sl)["fixes"], [])

    def test_summary_is_unique_not_null_and_references_history(self):
        """A direct SQL writer cannot bypass PenX's create-once guard."""
        import mysql.connector

        db.save_summary(self.sl, "first raw", "first analysis", "LOW", "fixture")
        with db_backend.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SHOW INDEX FROM summary WHERE Key_name = %s",
                           ("uq_summary_sl_no",))
            self.assertTrue(cursor.fetchall(), "MariaDB summary unique index missing")
            cursor.execute("SHOW COLUMNS FROM summary LIKE %s", ("sl_no",))
            self.assertEqual(cursor.fetchone()[2], "NO")
            for session in (self.sl, None, self.sl + 1234567):
                with self.subTest(session=session):
                    with self.assertRaises(mysql.connector.Error):
                        cursor.execute(
                            "INSERT INTO summary "
                            "(sl_no, raw_scan, ai_analysis, risk_level) "
                            "VALUES (%s, %s, %s, %s)",
                            (session, "overwrite", "bad", "HIGH"),
                        )
                        conn.commit()
                    conn.rollback()
            cursor.execute(
                "SELECT raw_scan, risk_level, COUNT(*) FROM summary "
                "WHERE sl_no = %s GROUP BY raw_scan, risk_level", (self.sl,)
            )
            self.assertEqual(cursor.fetchone(), ("first raw", "LOW", 1))

    def test_duplicate_mariadb_legacy_fixture_fails_without_data_loss(self):
        """Prove the migration DDL fails on duplicates, without ALTER IGNORE."""
        import mysql.connector

        with db_backend.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "CREATE TEMPORARY TABLE issue147_legacy "
                "(id INT AUTO_INCREMENT PRIMARY KEY, sl_no INT)"
            )
            cursor.execute(
                "INSERT INTO issue147_legacy (sl_no) VALUES (7), (7)"
            )
            with self.assertRaises(mysql.connector.Error):
                cursor.execute(
                    "ALTER TABLE issue147_legacy "
                    "MODIFY COLUMN sl_no INT NOT NULL, "
                    "ADD UNIQUE INDEX IF NOT EXISTS uq_summary_sl_no (sl_no)"
                )
            conn.rollback()
            cursor.execute("SELECT COUNT(*) FROM issue147_legacy WHERE sl_no = 7")
            self.assertEqual(cursor.fetchone()[0], 2)

    def test_failed_assessment_rolls_back_without_publishing_session(self):
        with self.assertRaises(ValueError):
            db.save_assessment(self.sl, {
                "risk_level": "LOW",
                "raw_scan": "fixture",
                "full_response": "fixture",
                "vulnerabilities": [
                    {"vuln_name": "first", "severity": "low", "description": "okay"},
                    {"vuln_name": "second", "severity": "invalid", "description": "bad"},
                ],
                "exploits": [],
            })
        data = db.get_session(self.sl)
        self.assertEqual(data["vulns"], [])
        self.assertIsNone(data["summary"])
        self.assertEqual(data["history"][3], "pending")
        self.assertNotIn(self.sl, [row[0] for row in db.get_all_history()])


    def test_external_evaluation_import_rollback_in_real_mariadb(self):
        """A failure on the second evaluation must undo the first correction."""
        db.save_assessment(self.sl, {
            "risk_level": "LOW",
            "raw_scan": "80/tcp open http",
            "full_response": "Synthetic review target",
            "vulnerabilities": [
                {"vuln_name": "First observation", "severity": "low",
                 "description": "Synthetic initial finding"},
                {"vuln_name": "Second observation", "severity": "low",
                 "description": "Synthetic second finding"},
            ],
            "exploits": [],
        }, model_name="integration-fixture")
        rows = db.get_session(self.sl)["vulns"]
        first, second = rows[0][0], rows[1][0]

        class InjectedCursor:
            def __init__(self, cursor):
                self.delegate = cursor
                self.evaluations = 0

            def execute(self, statement, params=()):
                if statement.lstrip().startswith("INSERT INTO evaluations"):
                    self.evaluations += 1
                    if self.evaluations == 2:
                        raise RuntimeError("injected MariaDB second evaluation failure")
                return self.delegate.execute(statement, params)

            def __getattr__(self, name):
                return getattr(self.delegate, name)

        class InjectedConnection:
            def __init__(self):
                self.delegate = db_backend.get_connection()

            def cursor(self):
                return InjectedCursor(self.delegate.cursor())

            def __getattr__(self, name):
                return getattr(self.delegate, name)

        review = ("EVAL: First observation\nVERDICT: hallucination\n"
                  "EVIDENCE: No matching scanner evidence\n"
                  "SEVERITY_CORRECT: no\nCVE_CORRECT: no\n"
                  "SOFTWARE_CORRECT: no\nFIX_CORRECT: no\n"
                  "EVAL: Second observation\nVERDICT: valid\n"
                  "SEVERITY_CORRECT: yes\nCVE_CORRECT: yes\n"
                  "SOFTWARE_CORRECT: yes\nFIX_CORRECT: yes\n")
        with patch("penx_app.storage.db_evals.get_connection", side_effect=InjectedConnection):
            with self.assertRaisesRegex(RuntimeError, "injected MariaDB"):
                db_evals.parse_evaluation_response(self.sl, "integration-fixture", review)
        with db_backend.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM evaluations WHERE sl_no = %s", (self.sl,))
            self.assertEqual(cursor.fetchone()[0], 0)
            cursor.execute("SELECT COUNT(*) FROM corrections WHERE sl_no = %s", (self.sl,))
            self.assertEqual(cursor.fetchone()[0], 0)
        self.assertEqual([item[0] for item in db.get_session(self.sl)["vulns"]],
                         [first, second])


if __name__ == "__main__":
    unittest.main(verbosity=2)
