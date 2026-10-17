"""NVD candidate identity and provider advisory URL integrity.

All responses are synthetic and injected: no external HTTP or scanner runs.
"""
from __future__ import annotations

import unittest
from unittest.mock import Mock

from penx_app.intelligence import cve_engine as engine
from penx_app.intelligence.cve_observations import parse_nmap_services


XML = (
    '<nmaprun><host><ports><port protocol="tcp" portid="22">'
    '<state state="open"/>'
    '<service name="ssh" product="OpenSSH" version="9.2">'
    '<cpe>cpe:/a:openbsd:openssh:9.2</cpe>'
    '</service></port></ports></host></nmaprun>'
)
RULE = {
    "vulnerable": True,
    "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
    "versionStartIncluding": "9.0",
    "versionEndExcluding": "9.4",
}


def record(identifier: str, references=None, status="Analyzed"):
    return {"cve": {
        "id": identifier, "vulnStatus": status,
        "configurations": [{"nodes": [{"operator": "OR", "cpeMatch": [RULE]}]}],
        "references": [] if references is None else references,
    }}


def query(items):
    response = Mock()
    response.status_code = 200
    response.headers = {}
    response.json.return_value = {
        "totalResults": len(items), "vulnerabilities": items,
    }
    client = Mock(return_value=response)
    result = engine.nvd_candidates(
        parse_nmap_services(XML)[0], http_get=client
    )
    response.close.assert_called_once()
    return result


class NvdCandidateInputValidationTests(unittest.TestCase):
    def test_invalid_cve_prefixes_do_not_become_advisory_links(self):
        invalid = (
            "CVE-invalid", "CVE-2026-test", "CVE-2026-12345\n[CRITICAL]",
            "CVE-2026-12345/../../other", "CVE-2026-000",
            "CVE-2026-123456789",
        )
        rows, warning = query([record(identifier) for identifier in invalid]
                              + [record("CVE-2026-12345")])
        self.assertEqual([row["id"] for row in rows], ["CVE-2026-12345"])
        self.assertEqual(rows[0]["url"],
                         "https://nvd.nist.gov/vuln/detail/CVE-2026-12345")
        self.assertIn("malformed", warning)

    def test_invalid_reference_does_not_discard_valid_nvd_candidate(self):
        refs = [
            {"url": "https://[invalid", "tags": ["Vendor Advisory"]},
            {"url": "https://vendor.example:abc/fix", "tags": ["Patch"]},
            {"url": "https://vendor.example\n@evil.example/x",
             "tags": ["Patch"]},
            {"url": "https://vendor.example/advisory", "tags": ["Vendor Advisory"]},
        ]
        rows, warning = query([record("CVE-2026-12345", refs)])
        self.assertEqual(warning, "")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["vendor_advisories"],
                         ["https://vendor.example/advisory"])

    def test_rejected_entries_never_claim_applicability(self):
        rows, warning = query([
            record("CVE-2026-12345", status="rejected"),
            record("cve-2026-55555"),
        ])
        self.assertEqual(warning, "")
        self.assertEqual([row["id"] for row in rows], ["CVE-2026-55555"])

    def test_reference_limits_and_bad_provider_containers_are_isolated(self):
        refs = [
            None, "unexpected string", {"url": "https://example.test/ignored",
                                         "tags": "Patch"},
            {"url": "https://vendor.example/one", "tags": ["Patch"]},
            {"url": "https://vendor.example/two", "tags": ["Vendor Advisory"]},
            {"url": "https://vendor.example/three", "tags": ["Patch"]},
        ]
        rows, warning = query([
            record("CVE-2026-12345", references={"unexpected": "object"}),
            record("CVE-2026-54321", refs),
        ])
        self.assertEqual(warning, "")
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["vendor_advisories"], [])
        self.assertEqual(rows[1]["vendor_advisories"],
                         ["https://vendor.example/one", "https://vendor.example/two"])


if __name__ == "__main__":
    unittest.main()
