"""Offline privacy regressions for ProjectDiscovery and ffuf JSONL summaries."""
from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from penx_app.scanners.native_web_scanners import summarize_output, _summary_url, _single_line
from penx_app.scanners.tools import ScannerOutput, _summarize_native_run


class NativeSummaryPrivacyTests(unittest.TestCase):
    def test_all_native_scanners_strip_query_values_and_fragments(self):
        fixtures = (
            ("nuclei", {
                "template-id": "test-template",
                "info": {"severity": "medium", "name": "Test"},
                "matched-at": "https://example.test/private?token=PRIVATE_NUCLEI#SECRET_FRAGMENT",
            }, "/private"),
            ("httpx", {
                "url": "https://example.test/login?cookie=PRIVATE_HTTPX#SECRET_FRAGMENT",
                "status_code": 200, "title": "Login", "tech": ["nginx"],
            }, "/login"),
            ("ffuf", {
                "url": "https://example.test/backup?key=PRIVATE_FFUF#SECRET_FRAGMENT",
                "status": 403,
            }, "/backup"),
        )
        for scanner, record, path in fixtures:
            with self.subTest(scanner=scanner):
                result, observed = summarize_output(scanner, json.dumps(record))
                self.assertTrue(observed)
                self.assertIn("https://example.test" + path, result)
                for marker in ("PRIVATE_", "SECRET_FRAGMENT", "?token", "?key", "?cookie"):
                    self.assertNotIn(marker, result)

    def test_plain_host_and_invalid_credentials_handled(self):
        self.assertEqual(_summary_url("example.test:8443?token=SECRET"), "example.test:8443")
        self.assertEqual(_summary_url("https://user:SECRET@example.test/a"),
                         "[URL CREDENTIALS REDACTED]")
        self.assertEqual(_summary_url("https://[::invalid"), "[INVALID URL]")
        self.assertEqual(_summary_url("https://example.test/a?key=SECRET"),
                         "https://example.test/a")

    def test_provider_control_and_bidi_chars_never_forge_output(self):
        raw = json.dumps({
            "url": "https://example.test/path?session=PRIVATE",
            "status_code": 200, "title": "Hi\u001b[2J\u202eFORGED\nSCANNER",
            "tech": ["python"]
        })
        summary, observed = summarize_output("httpx", raw)
        self.assertTrue(observed)
        for control in ("\x1b", "\u202e", "\nSCANNER"):
            self.assertNotIn(control, summary)
        self.assertIn("FORGED SCANNER", summary)
        self.assertEqual(_single_line("\x1bA\u202eB"), " A B")

    def test_noncomplete_output_does_not_disclose_raw_secret(self):
        for original_status in ("FAILED", "PARTIAL"):
            with self.subTest(original_status=original_status):
                original = ScannerOutput(
                    "GET https://example.test/auth?token=SECRET_SERVER_CREDENTIAL",
                    status=original_status, evidence=False
                )
                result = _summarize_native_run("nuclei", original)
                self.assertEqual(result.status, original_status)
                self.assertFalse(result.evidence)
                self.assertNotIn("SECRET_SERVER_CREDENTIAL", result)
                self.assertIn("did not complete", result)

    def test_unparseable_completed_scanner_output_does_not_echo_secret(self):
        raw = "GET https://example.test/callback?code=SUPER_SECRET"
        result = _summarize_native_run("httpx", ScannerOutput(raw))
        self.assertEqual(result.status, "FAILED")
        self.assertFalse(result.evidence)
        self.assertIn("no parseable JSONL", result)
        self.assertNotIn("SUPER_SECRET", result)

    def test_valid_native_summary_stays_complete(self):
        raw = json.dumps({"url": "https://example.test/", "status_code": 200, "tech": ["nginx"]})
        result = _summarize_native_run("httpx", ScannerOutput(raw))
        self.assertEqual(result.status, "COMPLETE")
        self.assertTrue(result.evidence)
        self.assertIn("technologies: nginx", result)


if __name__ == "__main__":
    unittest.main()
