"""PHP2Shell offline regression tests: no exploit, outbound traffic or raw log copying."""
from __future__ import annotations

from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from penx_app.intelligence.php2shell_local_audit import (
    MAX_LOCAL_BYTES, analyze_php2shell_local_artifacts,
)
from penx_app.cli.php2shell_audit_cli import audit_cli


class LocalTriageTests(unittest.TestCase):
    def test_no_logs_is_not_a_negative_result(self):
        report = analyze_php2shell_local_artifacts()
        self.assertEqual(report["triage"], "not_checked")
        self.assertFalse(report["exploit_confirmed"])
        self.assertEqual(
            report["configuration"]["settings"]["session.upload_progress.enabled"],
            "not_checked",
        )

    def test_php_ini_disabled_is_not_proof_of_safety(self):
        report = analyze_php2shell_local_artifacts(
            php_ini="; session.upload_progress.enabled=On\n"
                    "session.upload_progress.enabled = Off ; comment\n"
                    "session.use_strict_mode = On\n"
                    "fatal_error_backtraces=0\n"
        )
        settings = report["configuration"]["settings"]
        self.assertEqual(settings["session.upload_progress.enabled"], "disabled")
        self.assertEqual(settings["session.use_strict_mode"], "enabled")
        self.assertEqual(settings["fatal_error_backtraces"], "disabled")
        self.assertEqual(report["triage"], "not_checked")
        self.assertFalse(report["exploit_confirmed"])

    def test_conflicting_config_not_trusted(self):
        config = ("session.upload_progress.enabled = 0\n"
                  "session.upload_progress.enabled = 1\n")
        result = analyze_php2shell_local_artifacts(php_ini=config)
        self.assertEqual(
            result["configuration"]["settings"]["session.upload_progress.enabled"],
            "conflicting",
        )

    def test_log_signals_are_not_exploit_confirmation(self):
        access = ('10.1.2.3 - - "POST /upload.php HTTP/1.1" 500 92\n'
                  '10.1.2.3 - - "POST /form.php HTTP/1.1" 200 10 '
                  'PHP_SESSION_UPLOAD_PROGRESS\n')
        errors = ("PHP Fatal error: Allowed memory size of 8388608 bytes exhausted "
                  "in Unknown on line 0\n"
                  "child pid 88 exit signal Segmentation fault (11)\n")
        result = analyze_php2shell_local_artifacts(access_log=access, error_log=errors)
        self.assertEqual(result["triage"], "review_indicators")
        self.assertEqual(result["access_log"]["http_post_500_502_503"], 1)
        self.assertEqual(result["access_log"]["upload_progress_field_mentions"], 1)
        self.assertEqual(result["error_log"]["preinit_memory_errors"], 1)
        self.assertEqual(result["error_log"]["worker_crash_messages"], 1)
        self.assertFalse(result["exploit_confirmed"])
        self.assertNotIn("10.1.2.3", json.dumps(result))
        self.assertNotIn("/upload.php", json.dumps(result))

    def test_generic_http_500_is_not_assessed_as_attack(self):
        result = analyze_php2shell_local_artifacts(
            access_log='"POST /upload HTTP/1.1" 500 5'
        )
        self.assertEqual(result["access_log"]["http_post_500_502_503"], 1)
        self.assertEqual(result["triage"], "no_indicators_in_supplied_logs")

    def test_rejects_huge_artifacts(self):
        with self.assertRaises(ValueError):
            analyze_php2shell_local_artifacts(error_log="X" * (MAX_LOCAL_BYTES + 1))

    def test_cli_offline_version_and_ini(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            scan = root / "scan.txt"
            ini = root / "php.ini"
            scan.write_text("[ HTTP HEADERS OUTPUT ]\n" + "=" * 50
                            + "\nX-Powered-By: PHP/8.4.26\n", encoding="utf-8")
            ini.write_text("session.upload_progress.enabled=Off\n", encoding="utf-8")
            stdout = io.StringIO()
            with redirect_stdout(stdout), patch("socket.create_connection",
                                                  side_effect=AssertionError("network forbidden")):
                self.assertEqual(
                    audit_cli(["--scan-file", str(scan), "--php-ini", str(ini)]), 0
                )
            report = json.loads(stdout.getvalue())
            self.assertEqual(
                report["release_posture"]["status"], "pre_fix_release_observed"
            )
            self.assertEqual(report["local_triage"]["triage"], "not_checked")

    def test_cli_no_raw_log_leak(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "error.log"
            path.write_text("user-id PRIVATE-CUSTOMER-TOKEN\n", encoding="utf-8")
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                self.assertEqual(audit_cli(["--error-log", str(path)]), 0)
            self.assertNotIn("PRIVATE-CUSTOMER-TOKEN", stdout.getvalue())

    def test_bootstrap_dispatch(self):
        import sys
        from penx_app.bootstrap import main
        original = sys.argv
        try:
            sys.argv = ["penx", "--php2shell-audit", "--error-log", "local.log"]
            with patch("penx_app.cli.php2shell_audit_cli.audit_cli", return_value=0) as mocked:
                self.assertEqual(main(), 0)
                mocked.assert_called_once_with(["--error-log", "local.log"])
        finally:
            sys.argv = original


if __name__ == "__main__":
    unittest.main()
