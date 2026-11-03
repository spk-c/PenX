"""PX-004: verified backup/restore, migration dry run, rollback behavior.

All databases are disposable synthetic fixtures (legacy v2 and current v4).
No network, no subprocesses, no user data directory is touched.
"""
from __future__ import annotations

from contextlib import closing
import hashlib
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from penx_app.storage import backup as backup_store
from penx_app.storage.schema_migrations import SCHEMA, SCHEMA_VERSION, initialize_sqlite


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class BackupFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="penx-backup-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source_dir = self.root / "source"
        self.dest_dir = self.root / "backups"
        self.source_dir.mkdir()

    def make_legacy_v2(self, path: Path, *, duplicate: bool = False) -> None:
        conn = sqlite3.connect(str(path))
        conn.executescript(SCHEMA + "\nPRAGMA user_version=2;")
        conn.execute(
            "INSERT INTO history (sl_no, target, scan_date) "
            "VALUES (7, 'fixture.example.test', '2025-01-01')"
        )
        conn.execute(
            "INSERT INTO summary (id, sl_no, raw_scan, ai_analysis, risk_level) "
            "VALUES (9, 7, 'fixture raw', 'fixture analysis', 'LOW')"
        )
        if duplicate:
            conn.execute(
                "INSERT INTO summary (id, sl_no, raw_scan) VALUES (10, 7, 'duplicate')"
            )
        conn.commit()
        conn.close()

    def make_current(self, path: Path) -> None:
        conn = sqlite3.connect(str(path))
        initialize_sqlite(conn)
        conn.execute(
            "INSERT INTO history (target, scan_date) "
            "VALUES ('fixture.example.test', '2025-01-01')"
        )
        conn.execute(
            "INSERT INTO summary (sl_no, raw_scan, ai_analysis, risk_level) "
            "VALUES (1, 'fixture raw', 'fixture analysis', 'LOW')"
        )
        conn.commit()
        conn.close()

    def create_and_verify(self, source: Path) -> tuple[Path, dict]:
        db, manifest = backup_store.create_backup(source, self.dest_dir)
        report = backup_store.verify_backup(db)
        self.assertTrue(report["valid"], report["reasons"])
        return db, manifest


class CreateBackupTests(BackupFixture):
    def test_creates_valid_pair_with_matching_manifest(self):
        source = self.source_dir / "penx.db"
        self.make_current(source)
        db, manifest = self.create_and_verify(source)
        self.assertTrue(db.is_file())
        self.assertEqual(manifest["schema"], backup_store.BACKUP_SCHEMA)
        self.assertEqual(manifest["status"], "verified")
        self.assertEqual(manifest["file"], db.name)
        self.assertEqual(manifest["source_schema_version"], SCHEMA_VERSION)
        self.assertEqual(manifest["size_bytes"], db.stat().st_size)
        self.assertEqual(manifest["sha256"], _sha256(db))
        manifest_on_disk = json.loads(
            db.with_suffix(".json").read_text(encoding="utf-8")
        )
        self.assertEqual(manifest_on_disk, manifest)

    def test_never_overwrites_existing_backup(self):
        source = self.source_dir / "penx.db"
        self.make_current(source)
        first, _ = self.create_and_verify(source)
        first_hash = _sha256(first)
        second, _ = self.create_and_verify(source)
        self.assertNotEqual(first, second)
        self.assertEqual(_sha256(first), first_hash)

    def test_source_is_never_modified(self):
        source = self.source_dir / "penx.db"
        self.make_current(source)
        before = _sha256(source)
        with closing(sqlite3.connect(str(source))) as conn:
            self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0],
                            SCHEMA_VERSION)
        self.create_and_verify(source)
        self.assertEqual(_sha256(source), before)

    def test_open_wal_source_includes_committed_rows(self):
        source = self.source_dir / "penx.db"
        self.make_current(source)
        conn = sqlite3.connect(str(source))
        self.addCleanup(conn.close)
        self.assertEqual(conn.execute("PRAGMA journal_mode=WAL").fetchone()[0], "wal")
        conn.execute(
            "INSERT INTO history (target, scan_date) VALUES ('wal.example.test', '2025-02-02')"
        )
        conn.commit()
        db, _ = self.create_and_verify(source)
        with closing(sqlite3.connect(f"file:{db}?mode=ro", uri=True)) as ro:
            targets = {
                row[0]
                for row in ro.execute("SELECT target FROM history").fetchall()
            }
        self.assertEqual(targets, {"fixture.example.test", "wal.example.test"})

    def test_disk_full_on_final_rename_leaves_no_valid_backup(self):
        source = self.source_dir / "penx.db"
        self.make_current(source)
        real_replace = backup_store.os.replace

        def flaky_replace(src: str, dst: str):
            if str(dst).endswith(".sqlite"):
                raise OSError("disk full")
            return real_replace(src, dst)

        with patch.object(backup_store.os, "replace", side_effect=flaky_replace):
            with self.assertRaisesRegex(backup_store.BackupError, "Backup creation failed"):
                backup_store.create_backup(source, self.dest_dir)
        leftovers = sorted(p.name for p in self.dest_dir.iterdir())
        self.assertEqual(leftovers, [])
        with self.assertRaisesRegex(backup_store.BackupError, "No backup found"):
            backup_store.verify_backup(self.dest_dir)

    def test_kill_after_manifest_before_rename_is_not_valid(self):
        source = self.source_dir / "penx.db"
        self.make_current(source)
        db, manifest = self.create_and_verify(source)
        db.unlink()  # simulated process kill between manifest write and rename
        report = backup_store.verify_backup(db.with_suffix(".json"))
        self.assertFalse(report["valid"])
        self.assertIn("database file missing", "; ".join(report["reasons"]))


class VerifyBackupTests(BackupFixture):
    def test_tampered_file_fails_hash_check(self):
        source = self.source_dir / "penx.db"
        self.make_current(source)
        db, _ = self.create_and_verify(source)
        data = bytearray(db.read_bytes())
        data[len(data) // 2] ^= 0xFF
        db.write_bytes(bytes(data))
        report = backup_store.verify_backup(db)
        self.assertFalse(report["valid"])
        self.assertIn("sha256 mismatch", report["reasons"])

    def test_corrupt_manifest_is_invalid_not_raised(self):
        source = self.source_dir / "penx.db"
        self.make_current(source)
        db, _ = self.create_and_verify(source)
        db.with_suffix(".json").write_text("not json", encoding="utf-8")
        report = backup_store.verify_backup(db)
        self.assertFalse(report["valid"])
        self.assertIn("manifest unreadable", report["reasons"])

    def test_future_schema_version_is_rejected(self):
        source = self.source_dir / "penx.db"
        self.make_current(source)
        db, _ = self.create_and_verify(source)
        with closing(sqlite3.connect(str(db))) as conn:
            conn.execute(f"PRAGMA user_version={SCHEMA_VERSION + 1}")
        report = backup_store.verify_backup(db)
        self.assertFalse(report["valid"])
        self.assertIn("newer than", "; ".join(report["reasons"]))

    def test_directory_resolution_finds_a_valid_pair(self):
        source = self.source_dir / "penx.db"
        self.make_current(source)
        first, _ = self.create_and_verify(source)
        second, _ = self.create_and_verify(source)
        report = backup_store.verify_backup(self.dest_dir)
        self.assertTrue(report["valid"], report["reasons"])
        self.assertIn(report["db"], (str(first), str(second)))


class PreviewTests(BackupFixture):
    def test_current_backup_needs_no_migration(self):
        source = self.source_dir / "penx.db"
        self.make_current(source)
        db, _ = self.create_and_verify(source)
        preview = backup_store.preview_restore(db)
        self.assertEqual(preview["schema_version"], SCHEMA_VERSION)
        self.assertFalse(preview["migration"]["required"])
        self.assertTrue(preview["migration"]["succeeds"])
        self.assertEqual(preview["row_counts"]["history"], 1)
        self.assertEqual(preview["row_counts"]["summary"], 1)

    def test_legacy_migration_dry_run_succeeds_and_backup_unchanged(self):
        source = self.source_dir / "penx.db"
        self.make_legacy_v2(source)
        db, _ = self.create_and_verify(source)
        before = _sha256(db)
        preview = backup_store.preview_restore(db)
        self.assertEqual(preview["schema_version"], 2)
        self.assertTrue(preview["migration"]["required"])
        self.assertTrue(preview["migration"]["succeeds"])
        self.assertEqual(
            preview["migration"]["target_schema_version"], SCHEMA_VERSION
        )
        self.assertEqual(_sha256(db), before)
        # The throwaway copy is cleaned up, even the WAL sidecars.
        leftovers = [
            p.name for p in db.parent.iterdir() if p.name.startswith(".preview-")
        ]
        self.assertEqual(leftovers, [])

    def test_legacy_duplicate_rows_fail_migration_dry_run(self):
        source = self.source_dir / "penx.db"
        self.make_legacy_v2(source, duplicate=True)
        db, _ = self.create_and_verify(source)
        before = _sha256(db)
        preview = backup_store.preview_restore(db)
        self.assertTrue(preview["migration"]["required"])
        self.assertFalse(preview["migration"]["succeeds"])
        self.assertIn("migration v3 blocked", preview["migration"]["error"])
        self.assertEqual(_sha256(db), before)

    def test_preview_invalid_backup_raises(self):
        source = self.source_dir / "penx.db"
        self.make_current(source)
        db, _ = self.create_and_verify(source)
        db.unlink()
        with self.assertRaisesRegex(
            backup_store.BackupError, "Backup not valid"
        ):
            backup_store.preview_restore(db)


class RestoreTests(BackupFixture):
    def test_restore_replaces_live_and_keeps_pre_restore_backup(self):
        live = self.root / "live" / "penx.db"
        live.parent.mkdir()
        self.make_current(live)
        db, _ = self.create_and_verify(live)
        with closing(sqlite3.connect(str(live))) as conn:
            conn.execute(
                "INSERT INTO history (target, scan_date) "
                "VALUES ('after.example.test', '2025-03-03')"
            )
            conn.commit()
        result = backup_store.restore(db, live, self.dest_dir)
        self.assertTrue(Path(result["pre_restore_backup"]).is_file())
        with closing(sqlite3.connect(str(live))) as conn:
            targets = {
                row[0] for row in conn.execute("SELECT target FROM history")
            }
        self.assertEqual(targets, {"fixture.example.test"})
        pre = Path(result["pre_restore_backup"])
        with closing(sqlite3.connect(f"file:{pre}?mode=ro", uri=True)) as conn:
            targets = {
                row[0] for row in conn.execute("SELECT target FROM history")
            }
        self.assertEqual(
            targets, {"fixture.example.test", "after.example.test"}
        )

    def test_restore_creates_missing_live_database(self):
        live = self.root / "live" / "penx.db"
        live.parent.mkdir()
        source = self.source_dir / "penx.db"
        self.make_current(source)
        db, _ = self.create_and_verify(source)
        result = backup_store.restore(db, live, self.dest_dir)
        self.assertIsNone(result["pre_restore_backup"])
        with closing(sqlite3.connect(str(live))) as conn:
            self.assertEqual(
                conn.execute("PRAGMA user_version").fetchone()[0],
                SCHEMA_VERSION,
            )
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM history").fetchone()[0], 1)

    def test_restore_preserves_wal_journal_mode(self):
        live = self.root / "live" / "penx.db"
        live.parent.mkdir()
        self.make_current(live)
        with closing(sqlite3.connect(str(live))) as conn:
            self.assertEqual(conn.execute("PRAGMA journal_mode=WAL").fetchone()[0], "wal")
        db, _ = self.create_and_verify(live)
        backup_store.restore(db, live, self.dest_dir)
        with closing(sqlite3.connect(str(live))) as conn:
            self.assertEqual(conn.execute("PRAGMA journal_mode").fetchone()[0], "wal")
        leftovers = [
            p.name
            for p in live.parent.iterdir()
            if p.name.startswith("penx.db.restoring.tmp")
        ]
        self.assertEqual(leftovers, [])

    def test_restore_failure_keeps_live_byte_identical(self):
        live = self.root / "live" / "penx.db"
        live.parent.mkdir()
        self.make_current(live)
        before = _sha256(live)
        source = self.source_dir / "broken.db"
        self.make_legacy_v2(source, duplicate=True)
        db, _ = self.create_and_verify(source)
        with self.assertRaisesRegex(backup_store.BackupError, "migration v3 blocked"):
            backup_store.restore(db, live, self.dest_dir)
        self.assertEqual(_sha256(live), before)
        leftovers = [
            p.name
            for p in live.parent.iterdir()
            if p.name.startswith("penx.db.restoring.tmp")
        ]
        self.assertEqual(leftovers, [])
        # The source backup and the mandatory pre-restore backup both exist;
        # the pre-restore one carries the current live schema.
        versions = []
        for p in sorted(self.dest_dir.glob("penx-backup-*.sqlite")):
            with closing(sqlite3.connect(f"file:{p}?mode=ro", uri=True)) as conn:
                versions.append(conn.execute("PRAGMA user_version").fetchone()[0])
        self.assertEqual(sorted(versions), [2, SCHEMA_VERSION])
        for p in self.dest_dir.glob("penx-backup-*.sqlite"):
            report = backup_store.verify_backup(p)
            self.assertTrue(report["valid"], report["reasons"])

    def test_restore_invalid_backup_touches_nothing(self):
        live = self.root / "live" / "penx.db"
        live.parent.mkdir()
        self.make_current(live)
        before = _sha256(live)
        source = self.source_dir / "penx.db"
        self.make_current(source)
        db, _ = self.create_and_verify(source)
        data = bytearray(db.read_bytes())
        data[-1] ^= 0xFF
        db.write_bytes(bytes(data))
        with self.assertRaisesRegex(backup_store.BackupError, "Backup not valid"):
            backup_store.restore(db, live, self.dest_dir)
        self.assertEqual(_sha256(live), before)
        # Only the (invalid) backup pair itself is present: no pre-restore
        # backup and no staging file may appear before verification passes.
        leftovers = sorted(p.name for p in self.dest_dir.iterdir())
        self.assertEqual(
            leftovers, sorted([db.name, db.with_suffix(".json").name])
        )

    def test_legacy_roundtrip_migrates_and_preserves_rows(self):
        live = self.root / "live" / "penx.db"
        live.parent.mkdir()
        source = self.source_dir / "legacy.db"
        self.make_legacy_v2(source)
        db, _ = self.create_and_verify(source)
        result = backup_store.restore(db, live, self.dest_dir)
        self.assertEqual(result["schema_version"], SCHEMA_VERSION)
        with closing(sqlite3.connect(str(live))) as conn:
            self.assertEqual(
                conn.execute(
                    "SELECT target, status FROM history WHERE sl_no=7"
                ).fetchone(),
                ("fixture.example.test", "active"),
            )
            self.assertEqual(
                conn.execute(
                    "SELECT raw_scan, ai_analysis FROM summary WHERE id=9"
                ).fetchone(),
                ("fixture raw", "fixture analysis"),
            )


if __name__ == "__main__":
    unittest.main()
