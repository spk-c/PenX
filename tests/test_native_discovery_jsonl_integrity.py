"""Native discovery JSONL must not mistake parser failures for empty success.

All binaries and scan output are mocked; no network requests or processes.
"""
from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from penx_app.scanners import tools


DOMAIN = "example.test"


def run_subfinder(raw: str):
    with patch.object(tools, "find_native", return_value="subfinder.exe"), \
         patch.object(tools, "_run_external", return_value=raw):
        return tools.run_subfinder(DOMAIN)


def run_katana(raw: str):
    with patch.object(tools, "find_native", return_value="katana.exe"), \
         patch.object(tools, "_run_external", return_value=raw):
        return tools.run_katana("https://" + DOMAIN)


class NativeDiscoveryJsonlIntegrityTests(unittest.TestCase):
    def test_subfinder_malformed_nonempty_stdout_is_not_empty_success(self):
        for raw in ("This is not JSON", "[]", '{"host":123}', '{"host":null}'):
            with self.subTest(raw=raw):
                result = run_subfinder(raw)
                self.assertEqual(result.status, "FAILED")
                self.assertFalse(result.evidence)
                self.assertIn("malformed JSONL", result)

    def test_subfinder_rejects_hostnames_with_control_or_invalid_labels(self):
        for name in ("bad@.example.test", "bad..example.test",
                     "evil\n.example.test", "bad/path.example.test"):
            with self.subTest(name=name):
                result = run_subfinder(json.dumps({"host": name}))
                self.assertEqual(result.status, "FAILED")
                self.assertFalse(result.evidence)
                self.assertNotIn("[PASSIVE SUBDOMAIN INVENTORY", result)

    def test_subfinder_valid_rows_with_corrupt_rows_are_partial_with_evidence(self):
        raw = json.dumps({"host": "WWW.EXAMPLE.TEST."}) + "\nnot-json"
        result = run_subfinder(raw)
        self.assertEqual(result.status, "PARTIAL")
        self.assertTrue(result.evidence)
        self.assertIn("www.example.test", result)
        self.assertIn("malformed JSONL", result)

    def test_subfinder_healthy_valid_records_stay_complete(self):
        raw = json.dumps({"host": "www.example.test"}) + "\n" + json.dumps({
            "host": "outside.other.test"
        })
        result = run_subfinder(raw)
        self.assertEqual(result.status, "COMPLETE")
        self.assertTrue(result.evidence)
        self.assertIn("www.example.test", result)
        self.assertNotIn("outside.other.test", result)

    def test_katana_malformed_nonempty_stdout_is_not_empty_success(self):
        for raw in ("non-JSON stdout", "[]", '{"request":{}}',
                    '{"request":{"endpoint":12}}'):
            with self.subTest(raw=raw):
                result = run_katana(raw)
                self.assertEqual(result.status, "FAILED")
                self.assertFalse(result.evidence)
                self.assertIn("malformed JSONL", result)

    def test_katana_control_characters_are_not_published_as_evidence(self):
        raw = json.dumps({"request": {
            "endpoint": "https://example.test/path\n[FAKE SCANNER RESULT]"
        }})
        result = run_katana(raw)
        self.assertEqual(result.status, "FAILED")
        self.assertFalse(result.evidence)
        self.assertNotIn("[SAME-HOST CRAWL INVENTORY]", result)

    def test_katana_mixed_valid_and_bad_records_are_partial_and_scoped(self):
        valid = json.dumps({"request": {"endpoint": "https://example.test/safe"}})
        out_of_scope = json.dumps({"request": {
            "endpoint": "https://outside.example.test/ignored"
        }})
        result = run_katana(valid + "\n" + out_of_scope + "\nbroken-json")
        self.assertEqual(result.status, "PARTIAL")
        self.assertTrue(result.evidence)
        self.assertIn("https://example.test/safe", result)
        self.assertNotIn("https://outside.example.test/ignored", result)

    def test_katana_existing_timeout_contract_remains_partial(self):
        result = run_katana(json.dumps({
            "request": {"endpoint": "https://example.test/"},
            "error": "synthetic i/o timeout",
        }))
        self.assertEqual(result.status, "PARTIAL")
        self.assertFalse(result.evidence)
        self.assertIn("failed HTTP request", result)

    def test_katana_healthy_data_still_reports_complete_evidence(self):
        result = run_katana(json.dumps({
            "request": {"endpoint": "https://example.test/start#section"}
        }))
        self.assertEqual(result.status, "COMPLETE")
        self.assertTrue(result.evidence)
        self.assertIn("https://example.test/start", result)
        self.assertNotIn("#section", result)


if __name__ == "__main__":
    unittest.main()
