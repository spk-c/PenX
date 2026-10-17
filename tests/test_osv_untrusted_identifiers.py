"""Reject malformed upstream OSV identifiers without losing valid candidates.

All calls use an injected synthetic HTTP transport; no network or scanning.
"""
from __future__ import annotations

import unittest
from unittest.mock import Mock

from penx_app.intelligence import cve_engine
from penx_app.intelligence.cve_observations import parse_explicit_packages


PACKAGE = parse_explicit_packages("pkg:pypi/requests@2.31.0")[0]


def response(ids):
    r = Mock()
    r.status_code = 200
    r.json.return_value = {"vulns": [{"id": value} for value in ids]}
    r.raise_for_status.return_value = None
    return r


class OSVIdentifierTests(unittest.TestCase):
    def fetch(self, ids):
        r = response(ids)
        rows, warning = cve_engine.osv_candidates(
            PACKAGE, http_post=lambda *_args, **_kwargs: r)
        r.close.assert_called_once()
        return rows, warning

    def test_valid_osv_ecosystem_and_cve_ids_remain_supported(self):
        ids = ["GHSA-abcd-efgh-ijkl", "PYSEC-2024-123", "RUSTSEC-2025-0001",
               "GO-2024-1234", "CVE-2026-12345"]
        rows, warning = self.fetch(ids)
        self.assertEqual([item["id"] for item in rows], ids)
        self.assertEqual(warning, "")
        for item in rows:
            self.assertEqual(item["status"], "package-version-matched")
            self.assertTrue(item["url"].startswith("https://osv.dev/vulnerability/"))

    def test_control_characters_and_non_strings_are_never_exposed_as_ids(self):
        invalid = [
            None, {}, {"id": "GHSA-abcd-efgh-ijkl"}, 15, [],
            "GHSA-abc\n[NEW SCANNER RESULT]", "CVE-2026-12345/../../../x",
            "CVE-2026-abcde", "CVE-2026-12",
            "evil ID with spaces", "\tCVE-2026-12345",
            "A" * 512,
        ]
        rows, warning = self.fetch(invalid + ["CVE-2026-12345"])
        self.assertEqual([item["id"] for item in rows], ["CVE-2026-12345"])
        self.assertEqual(rows[0]["url"],
                         "https://osv.dev/vulnerability/CVE-2026-12345")
        self.assertIn("malformed candidate IDs", warning)

    def test_only_invalid_records_report_partial_data_not_false_no_findings(self):
        rows, warning = self.fetch(["CVE-invalid", None, " "])
        self.assertEqual(rows, [])
        self.assertIn("incomplete", warning)

    def test_no_malformed_rows_keeps_existing_empty_result_contract(self):
        rows, warning = self.fetch([])
        self.assertEqual((rows, warning), ([], ""))

    def test_valid_result_after_bad_sibling_is_retained(self):
        rows, warning = self.fetch([
            "something with whitespace", "GHSA-abcd-efgh-ijkl",
        ])
        self.assertEqual([item["id"] for item in rows], ["GHSA-abcd-efgh-ijkl"])
        self.assertIn("malformed", warning)


if __name__ == "__main__":
    unittest.main()
