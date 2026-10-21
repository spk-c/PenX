"""PHP2Shell offline advisory must never turn a version into confirmed RCE."""
import unittest

from penx_app.intelligence.php2shell_audit import assess_php2shell
from penx_app.reporting.machine_reports import report_payload, sarif_payload


def saved_scan(body):
    return "[ HTTP HEADERS OUTPUT ]\n" + "=" * 50 + "\n" + body + "\n"


class Php2ShellAuditTests(unittest.TestCase):
    def test_fixed_release_matrix(self):
        examples = (
            ("8.2.34", "pre_fix_release_observed"),
            ("8.2.35", "fixed_release_observed"),
            ("8.3.35", "pre_fix_release_observed"),
            ("8.3.36", "fixed_release_observed"),
            ("8.4.26", "pre_fix_release_observed"),
            ("8.4.27", "fixed_release_observed"),
            ("8.5.11", "pre_fix_release_observed"),
            ("8.5.12", "fixed_release_observed"),
            ("8.1.29", "unsupported_branch_observed"),
            ("7.4.33", "unsupported_branch_observed"),
        )
        for version, expected in examples:
            with self.subTest(version=version):
                result = assess_php2shell(saved_scan("X-Powered-By: PHP/" + version))
                self.assertEqual(result["status"], expected)
                self.assertFalse(result["exploit_tested"])

    def test_whatweb_and_windows_fallback(self):
        for line in ("https://example.test [200 OK] PHP[8.4.26]",
                     "Indicators: X-Powered-By=PHP/8.4.26"):
            with self.subTest(line=line):
                result = assess_php2shell("[ WEB FINGERPRINT OUTPUT ]\n" + line)
                self.assertEqual(result["status"], "pre_fix_release_observed")
                self.assertEqual(result["observations"][0]["source"], "WEB FINGERPRINT")

    def test_unrelated_model_text_cannot_be_mistaken_for_scanner(self):
        self.assertEqual(assess_php2shell("AI response: X-Powered-By: PHP/8.4.26")
                         ["status"], "unknown")
        self.assertEqual(assess_php2shell(saved_scan("Server: nginx"))["status"], "unknown")

    def test_failed_adapter_version_banner_is_not_trusted(self):
        text = ("[ HTTP HEADERS OUTPUT ]\n"
                + "=" * 50 + "\n"
                + "[PENX ADAPTER STATUS: FAILED; EVIDENCE: NO]\n"
                + "X-Powered-By: PHP/8.4.26\n")
        self.assertEqual(assess_php2shell(text)["status"], "unknown")

    def test_conflicting_multiple_headers_fail_closed(self):
        raw = saved_scan("X-Powered-By: PHP/8.4.26\nX-Powered-By: PHP/8.5.12")
        self.assertEqual(assess_php2shell(raw)["status"], "conflicting_or_multiple_versions")

    def test_enormous_input_does_not_scan(self):
        raw = saved_scan("X-Powered-By: PHP/8.4.26") + "a" * 2_000_001
        self.assertEqual(assess_php2shell(raw)["status"], "unknown")

    def test_exports_include_only_advisory_not_exploit_finding(self):
        data = {
            "history": (1, "example.test", "2026-10-21", "active"),
            "summary": (1, 1, saved_scan("X-Powered-By: PHP/8.4.26"),
                        "Offline observation", "UNKNOWN", "test-model", "2026-10-21"),
            "vulns": [], "corrections": [],
        }
        report = report_payload(data)
        self.assertEqual(report["php2shell"]["status"], "pre_fix_release_observed")
        self.assertFalse(report["php2shell"]["exploit_tested"])
        self.assertEqual(report["findings"], [])
        sarif = sarif_payload(data)
        self.assertEqual(sarif["runs"][0]["results"], [])
        self.assertEqual(
            sarif["runs"][0]["properties"]["php2shell"]["status"],
            "pre_fix_release_observed",
        )


if __name__ == "__main__":
    unittest.main()
