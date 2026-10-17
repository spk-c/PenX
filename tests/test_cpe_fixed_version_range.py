"""An explicit NVD CPE version remains a constraint even with range bounds.

Offline synthetic NVD rows; no HTTP, scanning, or production data.
"""
from __future__ import annotations

import unittest
from unittest.mock import Mock

from penx_app.intelligence.cve_engine import (
    applicability, nvd_candidates, version_applies,
)
from penx_app.intelligence.cve_observations import parse_nmap_services


XML = (
    '<nmaprun><host><ports><port protocol="tcp" portid="22">'
    '<state state="open"/>'
    '<service name="ssh" product="OpenSSH" version="9.2">'
    '<cpe>cpe:/a:openbsd:openssh:9.2</cpe>'
    '</service></port></ports></host></nmaprun>'
)
PRODUCT = parse_nmap_services(XML)[0]
BOUNDS = {"versionStartIncluding": "9.0", "versionEndExcluding": "10.0"}


def config(version):
    rule = {
        "vulnerable": True,
        "criteria": (
            f"cpe:2.3:a:openbsd:openssh:{version}:*:*:*:*:*:*:*"
        ),
        **BOUNDS,
    }
    return {"configurations": [
        {"nodes": [{"operator": "OR", "cpeMatch": [rule]}]}
    ]}


class ExactCPEVersionAndBoundsTests(unittest.TestCase):
    def test_explicit_nonmatching_version_overrides_matching_range(self):
        self.assertFalse(version_applies("9.2", BOUNDS, "8.0"))
        self.assertFalse(version_applies("8.0", BOUNDS, "8.0"))

    def test_explicit_matching_version_and_range_still_match(self):
        self.assertTrue(version_applies("9.2", BOUNDS, "9.2"))
        self.assertTrue(version_applies("9.2", BOUNDS, "*"))
        self.assertFalse(version_applies("10.0", BOUNDS, "*"))

    def test_unparseable_bounds_remain_uncertain_not_confirmed(self):
        malformed = {"versionEndExcluding": "9.3p1"}
        self.assertIsNone(version_applies("9.2", malformed, "9.2"))
        self.assertFalse(version_applies("9.2", malformed, "8.0"))

    def test_applicability_rejects_conflicting_concrete_rule(self):
        self.assertEqual(applicability(config("8.0"), PRODUCT), "no-match")
        self.assertEqual(
            applicability(config("9.2"), PRODUCT),
            "version-match-needs-vendor-review",
        )

    def test_nvd_candidates_do_not_promote_conflicting_version(self):
        row = {
            "cve": {
                "id": "CVE-2026-12345",
                "vulnStatus": "Analyzed",
                "references": [],
                **config("8.0"),
            }
        }
        response = Mock()
        response.status_code = 200
        response.headers = {}
        response.raise_for_status.return_value = None
        response.json.return_value = {
            "totalResults": 1,
            "vulnerabilities": [row],
        }
        output, warning = nvd_candidates(
            PRODUCT, http_get=lambda *args, **kwargs: response
        )
        self.assertEqual((output, warning), ([], ""))
        response.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
