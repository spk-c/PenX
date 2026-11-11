"""Synthetic, offline PX-004 historical fingerprint comparison regressions.

No SQL, database credentials, network, imports or external scanner activity.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from penx_app.application.mariadb_historical_compare import (
    SCHEMA, MAX_RECORD_BYTES, compare_historical_evidence,
)

H = lambda value: hashlib.sha256(value.encode("ascii")).hexdigest()


class HistoricalComparisonTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="penx-historical-")
        self.addCleanup(self.tmp.cleanup)
        self.folder = Path(self.tmp.name)
        self.source = self.folder / "historical-source.json"
        self.scratch = self.folder / "restored-scratch.json"
        self.source_record = self.fixture("source", "penx_ci_test")
        self.scratch_record = self.fixture("scratch", "penx_restore_fixture")
        self.save()

    def fixture(self, role, database):
        return {
            "schema": SCHEMA, "role": role, "database": database,
            "observed_at": "2026-11-01T12:00:00Z" if role == "source"
                           else "2026-11-02T12:00:00Z",
            "dump_sha256": H("offline-fixture-dump"),
            "structure_sha256": H("same-structure"),
            "tables": [
                {"name": "history", "rows": 2, "content_sha256": H("two-rows")},
                {"name": "summary", "rows": 1, "content_sha256": H("one-row")},
            ],
        }

    def save(self):
        self.source.write_text(json.dumps(self.source_record, sort_keys=True),
                               encoding="utf-8")
        self.scratch.write_text(json.dumps(self.scratch_record, sort_keys=True),
                                encoding="utf-8")

    def compare(self, *, pin=None):
        return compare_historical_evidence(
            self.source, self.scratch,
            expected_source_record_sha256=pin or hashlib.sha256(
                self.source.read_bytes()).hexdigest(),
            expected_dump_sha256=H("offline-fixture-dump"),
            source_database="penx_ci_test",
            scratch_database="penx_restore_fixture",
        )

    def test_matching_synthetic_fingerprints_never_certify_restore(self):
        result = self.compare()
        self.assertEqual(result["rows_compared"], 3)
        self.assertEqual(result["tables_compared"], 2)
        self.assertFalse(result["historical_source_authenticated"])
        self.assertFalse(result["historical_backup_rows_verified"])
        self.assertFalse(result["restore_available"])
        self.assertFalse(result["sql_executed"])
        self.assertFalse(result["database_modified"])

    def test_same_count_changed_content_fails(self):
        self.scratch_record["tables"][0]["content_sha256"] = H("changed-value")
        self.save()
        with self.assertRaisesRegex(ValueError, "fingerprints differ"):
            self.compare()

    def test_structure_or_table_count_change_fails(self):
        self.scratch_record["structure_sha256"] = H("other")
        self.save()
        with self.assertRaisesRegex(ValueError, "fingerprints differ"):
            self.compare()
        self.scratch_record = self.fixture("scratch", "penx_restore_fixture")
        self.scratch_record["tables"][0]["rows"] = 3
        self.save()
        with self.assertRaisesRegex(ValueError, "fingerprints differ"):
            self.compare()

    def test_external_source_digest_pin_detects_rewrite(self):
        pinned = hashlib.sha256(self.source.read_bytes()).hexdigest()
        self.source_record["tables"][0]["content_sha256"] = H("rewritten")
        self.save()
        with self.assertRaisesRegex(ValueError, "pin mismatch"):
            self.compare(pin=pinned)

    def test_malformed_and_truncated_json_fail(self):
        self.scratch.write_text('{"schema":', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "Malformed evidence"):
            self.compare()

    def test_duplicate_json_trust_field_fails(self):
        self.scratch.write_text(self.scratch.read_text(encoding="utf-8").replace(
            '"role": "scratch"', '"role": "scratch", "role": "source"'),
            encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "Malformed evidence record"):
            self.compare()

    def test_oversize_evidence_fails_before_parse(self):
        self.scratch.write_bytes(b" " * (MAX_RECORD_BYTES + 1))
        with self.assertRaisesRegex(ValueError, "size/type refused"):
            self.compare()

    def test_table_budget_and_duplicate_names_fail(self):
        self.scratch_record["tables"][0]["rows"] = 2001
        self.save()
        with self.assertRaisesRegex(ValueError, "row count"):
            self.compare()
        self.scratch_record = self.fixture("scratch", "penx_restore_fixture")
        self.scratch_record["tables"][1]["name"] = "history"
        self.save()
        with self.assertRaisesRegex(ValueError, "duplicate evidence table"):
            self.compare()

    def test_wrong_dump_digest_and_source_role_fail(self):
        self.scratch_record["dump_sha256"] = H("unrelated-dump")
        self.save()
        with self.assertRaisesRegex(ValueError, "dump binding mismatch"):
            self.compare()
        self.scratch_record = self.fixture("scratch", "penx_restore_fixture")
        self.source_record["role"] = "scratch"
        self.save()
        with self.assertRaisesRegex(ValueError, "stage or database mismatch"):
            self.compare()

    def test_time_order_is_evidence_only_not_historical_proof(self):
        self.scratch_record["observed_at"] = "2026-10-01T12:00:00Z"
        self.save()
        with self.assertRaisesRegex(ValueError, "predates"):
            self.compare()
        self.scratch_record["observed_at"] = "2026-99-01T12:00:00Z"
        self.save()
        with self.assertRaisesRegex(ValueError, "calendar date"):
            self.compare()

    def test_identity_of_source_and_scratch_files_refused(self):
        with self.assertRaisesRegex(ValueError, "different files"):
            compare_historical_evidence(
                self.source, self.source,
                expected_source_record_sha256=H("unused"),
                expected_dump_sha256=H("offline-fixture-dump"),
                source_database="penx_ci_test",
                scratch_database="penx_restore_fixture",
            )

    def test_symlink_refused_if_supported(self):
        target = self.folder / "scratch-link.json"
        try:
            target.symlink_to(self.scratch)
        except (OSError, NotImplementedError):
            self.skipTest("Symlinks not supported on this test host")
        with self.assertRaisesRegex(ValueError, "symlink refused"):
            compare_historical_evidence(
                self.source, target,
                expected_source_record_sha256=hashlib.sha256(
                    self.source.read_bytes()).hexdigest(),
                expected_dump_sha256=H("offline-fixture-dump"),
                source_database="penx_ci_test",
                scratch_database="penx_restore_fixture",
            )


if __name__ == "__main__":
    unittest.main()
