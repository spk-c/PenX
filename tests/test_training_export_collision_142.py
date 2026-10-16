"""Two exports in the same second must preserve earlier training artifacts."""
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from penx_app.storage import db_training
from penx_app.storage.db_backend import SQLiteConnection
from penx_app.storage.schema_migrations import initialize_sqlite


class TrainingCollisionTests(unittest.TestCase):
    def test_training_files_are_exclusive_and_stats_failure_does_not_clobber(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            database = root / "test.sqlite"
            with closing(sqlite3.connect(database)) as con:
                initialize_sqlite(con)
                con.execute("INSERT INTO history (sl_no, target, scan_date, status) "
                            "VALUES (1,'example.test','today','active')")
                con.execute("INSERT INTO summary "
                            "(sl_no,raw_scan,ai_analysis,risk_level,model_name,generated_at) "
                            "VALUES (1,'fixture','fixture','LOW','fixture','today')")
                con.execute("INSERT INTO vulnerabilities "
                            "(id,sl_no,vuln_name,severity,confidence,port,service,description) "
                            "VALUES (11,1,'reviewed','low','confirmed','443','https','fixture')")
                con.execute("INSERT INTO corrections "
                            "(sl_no,vuln_id,status,original_text,corrected_text,reason,corrected_at) "
                            "VALUES (1,11,'verified','','','verified','today')")
                con.commit()

            def connection():
                return SQLiteConnection(sqlite3.connect(database))

            with patch.object(db_training, "get_connection", side_effect=connection), \
                 patch.object(db_training, "datetime") as date:
                date.now.return_value.strftime.return_value = "20261015_123456"
                first = Path(db_training.export_training_data(str(root)))
                baseline = first.read_bytes()
                first_stats = first.with_name(first.stem + "_stats.json")
                baseline_stats = first_stats.read_bytes()
                second = Path(db_training.export_training_data(str(root)))
                self.assertNotEqual(first, second)
                self.assertEqual(first.read_bytes(), baseline)
                self.assertEqual(first_stats.read_bytes(), baseline_stats)
                second_stats = second.with_name(second.stem + "_stats.json")
                self.assertTrue(second_stats.is_file())
                self.assertTrue(json.loads(second_stats.read_text(encoding="utf-8"))["total_pairs"])

                original = db_training.publish_unique

                def fail_on_stats(directory, stem, suffix, text):
                    if suffix == ".json":
                        raise OSError("injected stats failure")
                    return original(directory, stem, suffix, text)

                with patch.object(db_training, "publish_unique", side_effect=fail_on_stats):
                    with self.assertRaisesRegex(OSError, "injected stats failure"):
                        db_training.export_training_data(str(root))

                self.assertEqual(set(root.glob("penx_training_*.jsonl")), {first, second})
                self.assertEqual(first.read_bytes(), baseline)
                self.assertEqual(first_stats.read_bytes(), baseline_stats)


if __name__ == "__main__":
    unittest.main()
