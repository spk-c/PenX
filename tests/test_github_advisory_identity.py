"""GitHub advisory IDs and links are untrusted provider fields.

Synthetic responses only; no GitHub API or target network access.
"""
from __future__ import annotations

import unittest
from unittest.mock import Mock

from penx_app.intelligence import cve_engine
from penx_app.intelligence.cve_observations import parse_explicit_packages


PACKAGE = parse_explicit_packages("pkg:pypi/requests@2.31.0")[0]
GHSA = "GHSA-abcd-efgh-ijkl"


def record(*, ghsa=GHSA, cve="CVE-2026-12345", url=None):
    return {
        "ghsa_id": ghsa, "cve_id": cve,
        "html_url": ("https://github.com/advisories/" + ghsa
                     if url is None else url),
    }


class AdvisoryIdentityTests(unittest.TestCase):
    def fetch(self, rows):
        res = Mock()
        res.status_code = 200
        res.headers = {}
        res.raise_for_status.return_value = None
        res.json.return_value = rows
        data, note = cve_engine.github_candidates(
            PACKAGE, http_get=lambda *a, **kw: res
        )
        res.close.assert_called_once()
        return data, note

    def test_normal_ghsa_with_cve_keeps_existing_candidate_contract(self):
        rows, note = self.fetch([record()])
        self.assertEqual(note, "")
        self.assertEqual(rows[0]["id"], "CVE-2026-12345")
        self.assertEqual(rows[0]["url"],
                         "https://github.com/advisories/" + GHSA)
        self.assertEqual(rows[0]["status"], "package-version-matched")

    def test_ghsa_without_optional_cve_remains_valid(self):
        rows, note = self.fetch([record(cve=None)])
        self.assertEqual(note, "")
        self.assertEqual(rows[0]["id"], GHSA.upper())

    def test_fake_urls_or_conflicting_ids_never_become_advisory_evidence(self):
        urls = [
            "https://github.com/advisories/" + GHSA + "\n[FAKE CVE]",
            "https://github.com/advisories/" + GHSA + "/../wrong",
            "https://github.com/advisories/GHSA-xxxx-yyyy-zzzz",
            "https://github.com/advisories/" + GHSA + "?some=secret",
            "https://github.com/advisories/" + GHSA + "#other",
            "https://github.com/advisories/" + GHSA + "@other.example",
            "https://github.com/advisories/" + GHSA + "evil",
        ]
        for url in urls:
            with self.subTest(url=url):
                data, note = self.fetch([record(url=url)])
                self.assertEqual(data, [])
                self.assertIn("malformed", note)

    def test_bad_identifiers_do_not_discard_good_sibling_rows(self):
        bad = [
            None, "corrupt upstream row", record(ghsa="GHSA-invalid"),
            record(ghsa="GHSA-abcd-efgh-ijkl\nBREAK"),
            record(ghsa={"invalid": 1}, url="https://github.com/advisories/id"),
        ]
        data, note = self.fetch(bad + [record()])
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["id"], "CVE-2026-12345")
        self.assertIn("incomplete", note)

    def test_malformed_cve_alias_falls_back_to_verified_ghsa(self):
        data, note = self.fetch([record(cve="CVE-2026-BROKEN")])
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["id"], GHSA.upper())
        self.assertIn("malformed", note)
        self.assertNotIn("BROKEN", repr(data))

    def test_invalid_only_response_is_not_silent_negative(self):
        data, note = self.fetch([{"cve_id": "CVE-2026-12345"}])
        self.assertEqual(data, [])
        self.assertIn("incomplete", note)


if __name__ == "__main__":
    unittest.main()
