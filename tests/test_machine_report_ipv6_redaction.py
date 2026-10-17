"""Redacted machine reports must conceal literal IPv6 addresses too.

Synthetic in-memory sessions only. No scanners, network or user files.
"""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from penx_app.reporting.machine_reports import (
    report_payload, sarif_payload, write_machine_report,
)


def session(*, target="example.test"):
    quote = "443/tcp open https"
    return {
        "history": (31, target, "2026-10-17", "active"),
        "summary": (1, 31, "[ NMAP OUTPUT ]\n" + quote,
                    "synthetic summary", "LOW"),
        "vulns": [(
            71, 31, "Test host 2001:db8::1234",
            "medium", "confirmed",
            "[fe80::1%3]:443",
            "https://[::ffff:192.0.2.42]/",
            "Evidence: " + quote
            + "\nObserved 2606:4700:4700::1111 and 192.0.2.5"
            + "\nEndpoint https://[2001:db8::10]:8443"
            + "\nTicket 12:34 is not an IP address",
        )],
        "fixes": [], "corrections": [],
    }


class RedactedIpv6ExportsTests(unittest.TestCase):
    def test_json_export_masks_independent_ipv6_and_ipv4_literals(self):
        payload = report_payload(session(), redact=True)
        serialized = json.dumps(payload)
        for sensitive in (
            "2001:db8::1234", "fe80::1%3", "::ffff:192.0.2.42",
            "2606:4700:4700::1111", "192.0.2.5", "2001:db8::10",
        ):
            with self.subTest(address=sensitive):
                self.assertNotIn(sensitive, serialized)
        self.assertIn("[IPv6 REDACTED]", serialized)
        self.assertIn("[IPv4 REDACTED]", serialized)
        self.assertIn("Ticket 12:34 is not an IP address", serialized)
        self.assertEqual(payload["findings"][0]["status"], "scanner-quote-matched")

    def test_sarif_contains_no_unredacted_ipv6(self):
        serialized = json.dumps(sarif_payload(session(), redact=True))
        self.assertNotIn("2001:db8::1234", serialized)
        self.assertNotIn("fe80::1%3", serialized)
        self.assertNotIn("2606:4700:4700::1111", serialized)
        self.assertIn("[IPv6 REDACTED]", serialized)
        self.assertEqual(json.loads(serialized)["version"], "2.1.0")

    def test_ipv6_target_and_other_ipv6_are_masked_independently(self):
        payload = report_payload(session(target="2001:db8::ff"), redact=True)
        serialized = json.dumps(payload)
        self.assertNotIn("2001:db8::ff", serialized)
        self.assertNotIn("2001:db8::1234", serialized)
        self.assertEqual(payload["target"], "[TARGET REDACTED]")

    def test_unredacted_export_retains_evidence_and_ipv6(self):
        payload = report_payload(session(), redact=False)
        serialized = json.dumps(payload)
        self.assertIn("2001:db8::1234", serialized)
        self.assertIn("fe80::1%3", serialized)
        self.assertIn("2606:4700:4700::1111", serialized)
        self.assertIn("443/tcp open https", serialized)

    def test_persisted_redacted_json_and_sarif_contain_no_ipv6(self):
        with tempfile.TemporaryDirectory() as folder:
            for fmt in ("json", "sarif"):
                with self.subTest(format=fmt):
                    path = write_machine_report(session(), folder, fmt=fmt,
                                                redact=True)
                    self.assertTrue(Path(path).exists())
                    body = Path(path).read_text(encoding="utf-8")
                    self.assertIn("[IPv6 REDACTED]", body)
                    self.assertNotIn("2001:db8::1234", body)
                    self.assertNotIn("fe80::1%3", body)


if __name__ == "__main__":
    unittest.main()
