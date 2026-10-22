"""Disposable SQLite/filesystem regressions; never access saved assessments."""
from contextlib import closing
from dataclasses import replace
import os
from pathlib import Path
import sqlite3
import stat
import tempfile
import unittest
from unittest.mock import patch

from penx_app.domain.raw_artifact import MAX_ARTIFACT_BYTES
from penx_app.domain.scan_models import ScannerResult, ScanResult
from penx_app.reporting.report_batch import publication_lock
from penx_app.storage.db_backend import SQLiteCursor
from penx_app.storage.raw_artifacts import retain_artifacts, validate_artifact


class StorageRecoveryAuditTests(unittest.TestCase):
    def test_sqlite_backslash_does_not_escape_closing_quote(self):
        with closing(sqlite3.connect(':memory:')) as connection:
            cursor = SQLiteCursor(connection.cursor())
            cursor.execute("SELECT '\\', %s, '%s'", ('bound',))
            self.assertEqual(cursor.fetchone(), ('\\', 'bound', '%s'))
            cursor.execute('SELECT "\\", %s', (42,))
            self.assertEqual(cursor.fetchone(), ('\\', 42))

    def test_publication_lock_rejects_unbounded_or_invalid_timeout_before_io(self):
        with tempfile.TemporaryDirectory() as root:
            for index, timeout in enumerate((float('nan'), float('inf'), -float('inf'), True, '30', None)):
                folder = Path(root) / f'reports_{index}'
                with self.subTest(timeout=timeout):
                    with self.assertRaises(ValueError):
                        with publication_lock(folder, 1, timeout=timeout):
                            pass
                    self.assertFalse(folder.exists())

    def test_artifact_checks_the_opened_file_type(self):
        with tempfile.TemporaryDirectory() as root:
            stored = retain_artifacts(ScanResult((ScannerResult('nmap', 'sample', 'COMPLETE', True),)), root).results[0]
            # Simulate the path changing after the regular-path checks but
            # before the descriptor is inspected (a non-regular opened file).
            fake_stat = type('Stat', (), {'st_mode': stat.S_IFCHR, 'st_dev': 0, 'st_ino': 0})()
            with patch('os.fstat', return_value=fake_stat):
                with self.assertRaises(ValueError):
                    validate_artifact(stored, root)

    def test_changed_artifact_identity_is_rejected_and_read_handle_closed(self):
        with tempfile.TemporaryDirectory() as root:
            stored = retain_artifacts(ScanResult((ScannerResult('nmap', 'sample', 'COMPLETE', True),)), root).results[0]
            actual_stat, actual_fdopen = os.fstat, os.fdopen
            streams = []
            def different_file(fd):
                original = actual_stat(fd)
                return type('Stat', (), {'st_mode': original.st_mode, 'st_dev': original.st_dev,
                                         'st_ino': original.st_ino + 1})()
            def capture_handle(fd, mode):
                stream = actual_fdopen(fd, mode)
                streams.append(stream)
                return stream
            with patch('os.fstat', side_effect=different_file), patch('os.fdopen', side_effect=capture_handle):
                with self.assertRaisesRegex(ValueError, 'unchanged regular file'):
                    validate_artifact(stored, root)
            self.assertEqual(len(streams), 1)
            self.assertTrue(streams[0].closed)

    def test_zero_and_fractional_publication_timeouts_remain_valid(self):
        with tempfile.TemporaryDirectory() as root:
            for timeout in (0, 0.1):
                with publication_lock(Path(root), 1, timeout=timeout):
                    pass

    def test_oversized_new_text_cannot_keep_a_stale_capture_reference(self):
        with tempfile.TemporaryDirectory() as root:
            stored = retain_artifacts(ScanResult((ScannerResult('nmap', 'sample', 'COMPLETE', True),)), root).results[0]
            for text in ('x' * (MAX_ARTIFACT_BYTES + 1), '\u2603' * (MAX_ARTIFACT_BYTES // 2)):
                with self.subTest(multibyte=text.startswith('\u2603')):
                    changed = replace(stored, text=text)
                    result = retain_artifacts(ScanResult((changed,)), root)
                    self.assertIsNone(result.results[0].raw_artifact)
            self.assertEqual(len(list(Path(root).iterdir())), 1)


if __name__ == '__main__':
    unittest.main()
