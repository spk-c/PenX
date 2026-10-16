"""MariaDB dump/restore CI is restricted to disposable service fixtures."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class MariaDBBackupRestoreContracts(unittest.TestCase):
    def test_ci_runs_actual_dump_and_restore(self):
        workflow = (ROOT / ".github/workflows/mariadb-integration.yml").read_text()
        self.assertIn("python tests/mariadb_integration.py", workflow)
        self.assertIn("bash scripts/ci_mariadb_backup_restore.sh", workflow)
        self.assertIn("job.services.mariadb.id", workflow)

    def test_fail_closed_ci_only_database_guards(self):
        script = (ROOT / "scripts/ci_mariadb_backup_restore.sh").read_text()
        for item in ("PENX_MARIADB_TEST", "penx_ci_test", "penx_ci_restore_test",
                     "restore-fixture.invalid", "mariadb-dump", "--single-transaction",
                     "uq_summary_sl_no", "trap 'rm -f"):
            self.assertIn(item, script)
        self.assertNotIn("DROP DATABASE", script)


if __name__ == "__main__":
    unittest.main()
