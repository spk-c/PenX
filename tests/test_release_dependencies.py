"""Fail-closed offline regression tests for frozen dependency verification."""
from __future__ import annotations

from pathlib import Path
import subprocess
import tempfile
import unittest

from scripts import verify_frozen_runtime as verifier


EXPECTED = {"certifi": "2026.10.23", "dnspython": "2.9.2", "pillow": "13.0.0"}


def fake_run(report: str, status: int = 0):
    def run(_argv, **_kwargs):
        return subprocess.CompletedProcess([], status, report, "")
    return run


class FrozenDependencyVerificationTests(unittest.TestCase):
    def test_locked_versions_are_parsed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "requirements.lock.txt"
            path.write_text(
                "certifi==2026.10.23 \\\n"
                "dnspython==2.9.2 \\\n"
                "Pillow==13.0.0 \\\n", encoding="utf-8")
            self.assertEqual(verifier.locked_versions(path), EXPECTED)

    def test_missing_or_duplicate_locked_package_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "lock.txt"
            path.write_text("certifi==2026.10.23\ndnspython==2.9.2\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Missing"):
                verifier.locked_versions(path)
            path.write_text(
                "certifi==1\ncertifi==2\ndnspython==2.9.2\npillow==13.0.0\n",
                encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Duplicate"):
                verifier.locked_versions(path)

    def test_frozen_report_exact_versions_pass(self):
        report = '{"frozen":true,"packages":{"certifi":"2026.10.23","dnspython":"2.9.2","pillow":"13.0.0"}}'
        verifier.verify_executable(Path("PenX.exe"), EXPECTED, run=fake_run(report))

    def test_source_environment_does_not_count_as_a_frozen_binary(self):
        report = '{"frozen":false,"packages":{"certifi":"2026.10.23","dnspython":"2.9.2","pillow":"13.0.0"}}'
        with self.assertRaisesRegex(ValueError, "frozen"):
            verifier.verify_executable(Path("PenX.exe"), EXPECTED, run=fake_run(report))

    def test_old_vulnerable_dependency_is_refused(self):
        report = '{"frozen":true,"packages":{"certifi":"2026.10.23","dnspython":"2.8.0","pillow":"13.0.0"}}'
        with self.assertRaisesRegex(ValueError, "dnspython version mismatch"):
            verifier.verify_executable(Path("PenX.exe"), EXPECTED, run=fake_run(report))

    def test_malformed_and_incomplete_reports_fail_closed(self):
        for report in ("not JSON", "{}", '{"frozen":true,"packages":{}}'):
            with self.subTest(report=report), self.assertRaises(ValueError):
                verifier.verify_executable(Path("PenX.exe"), EXPECTED, run=fake_run(report))

    def test_nonzero_exit_is_refused(self):
        with self.assertRaisesRegex(ValueError, "exit 1"):
            verifier.verify_executable(Path("PenX.exe"), EXPECTED, run=fake_run("", 1))


if __name__ == "__main__":
    unittest.main()
