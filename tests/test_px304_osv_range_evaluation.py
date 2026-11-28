"""PX-304 opt-in OSV SEMVER range evaluation: offline and fail-closed.

The default comparison still defers range semantics. Passing
evaluate_ranges=True evaluates only SEMVER ranges against the exact local
SBOM identities and fails closed on any unparseable version or malformed
range shape.
"""
from __future__ import annotations

from contextlib import redirect_stdout
from io import StringIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from penx_app.application.sbom_inspection import main as sbom_cli
from penx_app.intelligence import osv_snapshot_match as om
from penx_app.intelligence.sbom_inventory import SBOMError


class OfflineOSVRangeEvaluationTests(unittest.TestCase):
    def setUp(self):
        root = tempfile.TemporaryDirectory(prefix="px304-osv-ranges-")
        self.addCleanup(root.cleanup)
        self.sbom = Path(root.name) / "local-sbom.json"
        self.osv = Path(root.name) / "local-osv.json"
        self.sbom_data = {
            "bomFormat": "CycloneDX", "specVersion": "1.6",
            "components": [
                {"type": "library", "name": "Django", "version": "5.1.0",
                 "purl": "pkg:pypi/Django@5.1.0"},
                {"type": "library", "name": "Django", "version": "5.2.0",
                 "purl": "pkg:pypi/Django@5.2.0"},
                {"type": "library", "name": "Django", "version": "4.2.0",
                 "purl": "pkg:pypi/Django@4.2.0"},
            ],
        }
        self.osv_data = {"vulns": [
            {
                "id": "CVE-2026-11111",
                "affected": [
                    {
                        "package": {"name": "django", "ecosystem": "PyPI"},
                        "ranges": [
                            {
                                "type": "SEMVER",
                                "events": [
                                    {"introduced": "5.0.0", "ended": "5.2.0"}
                                ],
                            }
                        ],
                    }
                ],
            }
        ]}
        self.write()

    def write(self):
        self.sbom.write_text(json.dumps(self.sbom_data), encoding="utf-8")
        self.osv.write_text(json.dumps(self.osv_data), encoding="utf-8")

    def compare(self, *, evaluate_ranges=False, reveal=False):
        return om.compare_local_osv_snapshot(
            self.sbom, self.osv,
            include_candidates=reveal, evaluate_ranges=evaluate_ranges)

    def test_default_mode_still_defers_ranges(self):
        result = self.compare()
        self.assertFalse(result["affected_ranges_evaluated"])
        self.assertEqual(result["uninterpreted_range_entries"], 1)
        self.assertEqual(result["evaluated_range_entries"], 0)
        self.assertEqual(result["unsupported_or_unversioned_affected_entries"], 1)
        self.assertEqual(result["matched_advisory_package_pairs"], 0)
        self.assertIsNone(result["candidates"])

    def test_optin_range_matches_installed_version_within_span(self):
        result = self.compare(evaluate_ranges=True)
        self.assertTrue(result["affected_ranges_evaluated"])
        self.assertEqual(result["uninterpreted_range_entries"], 0)
        self.assertEqual(result["evaluated_range_entries"], 1)
        self.assertEqual(result["unsupported_or_unversioned_affected_entries"], 0)
        self.assertEqual(result["matched_advisory_package_pairs"], 1)
        self.assertIsNone(result["candidates"])

    def test_optin_ended_version_is_exclusive(self):
        result = self.compare(evaluate_ranges=True, reveal=True)
        self.assertEqual(result["candidates"], [
            {"advisory_id": "CVE-2026-11111", "ecosystem": "PyPI",
             "name": "django", "version": "5.1.0"},
        ])

    def test_optin_open_ended_range_includes_newer_versions(self):
        self.osv_data = {"vulns": [
            {
                "id": "CVE-2026-11111",
                "affected": [
                    {
                        "package": {"name": "django", "ecosystem": "PyPI"},
                        "ranges": [
                            {"type": "SEMVER", "events": [{"introduced": "0"}]}
                        ],
                    }
                ],
            }
        ]}
        self.write()
        result = self.compare(evaluate_ranges=True, reveal=True)
        self.assertEqual(result["candidates"], [
            {"advisory_id": "CVE-2026-11111", "ecosystem": "PyPI",
             "name": "django", "version": "4.2.0"},
            {"advisory_id": "CVE-2026-11111", "ecosystem": "PyPI",
             "name": "django", "version": "5.1.0"},
            {"advisory_id": "CVE-2026-11111", "ecosystem": "PyPI",
             "name": "django", "version": "5.2.0"},
        ])

    def test_optin_multiple_event_spans_are_unioned(self):
        self.osv_data = {"vulns": [
            {
                "id": "CVE-2026-11111",
                "affected": [
                    {
                        "package": {"name": "django", "ecosystem": "PyPI"},
                        "ranges": [
                            {
                                "type": "SEMVER",
                                "events": [
                                    {"introduced": "5.0.0", "ended": "5.1.0"},
                                    {"introduced": "5.2.0"},
                                ],
                            }
                        ],
                    }
                ],
            }
        ]}
        self.write()
        result = self.compare(evaluate_ranges=True, reveal=True)
        # The SBOM has 5.1.0/5.2.0/4.2.0: 5.1.0 is excluded by the first
        # span's ended bound and only 5.2.0 falls into the second span.
        self.assertEqual(result["candidates"], [
            {"advisory_id": "CVE-2026-11111", "ecosystem": "PyPI",
             "name": "django", "version": "5.2.0"},
        ])

    def test_optin_range_only_entry_is_not_unsupported(self):
        result = self.compare(evaluate_ranges=True)
        self.assertEqual(result["unsupported_or_unversioned_affected_entries"], 0)
        self.assertEqual(result["matched_advisory_package_pairs"], 1)

    def test_optin_unparseable_installed_version_fails_closed(self):
        # "a" passes the SBOM version regex but is not a PEP 440 version.
        self.sbom_data = {
            "bomFormat": "CycloneDX", "specVersion": "1.6",
            "components": [
                {"type": "library", "name": "Django", "version": "a",
                 "purl": "pkg:pypi/Django@a"},
            ],
        }
        self.write()
        with self.assertRaises(SBOMError):
            self.compare(evaluate_ranges=True)
        # Default mode never parses versions, so it keeps working.
        self.compare()

    def test_optin_invalid_range_shape_fails_closed(self):
        for ranges in (
            [{"type": "DEBIAN", "events": [{"introduced": "0"}]}],
            [{"type": "SEMVER"}],
            [{"type": "SEMVER", "events": []}],
            [{"type": "SEMVER", "events": [None]}],
            ["untrusted"],
        ):
            self.osv_data = {"vulns": [
                {
                    "id": "CVE-2026-11111",
                    "affected": [
                        {
                            "package": {"name": "django", "ecosystem": "PyPI"},
                            "ranges": ranges,
                        }
                    ],
                }
            ]}
            self.write()
            with self.subTest(ranges=ranges), self.assertRaises(SBOMError):
                self.compare(evaluate_ranges=True)
            # Default mode never interprets the range shape.
            self.compare()

    def test_optin_invalid_range_bounds_fail_closed(self):
        for events in (
            [{}],
            [{"introduced": "not-a-version"}],
            [{"introduced": "5.0.0", "ended": "also-bad"}],
            [{"introduced": "5.0.0", "ended": "5.0.0"}],
            [{"introduced": "5.1.0", "ended": "5.0.0"}],
            [{"introduced": "5.0.0", "ended": 123}],
        ):
            self.osv_data = {"vulns": [
                {
                    "id": "CVE-2026-11111",
                    "affected": [
                        {
                            "package": {"name": "django", "ecosystem": "PyPI"},
                            "ranges": [
                                {"type": "SEMVER", "events": events}
                            ],
                        }
                    ],
                }
            ]}
            self.write()
            with self.subTest(events=events), self.assertRaises(SBOMError):
                self.compare(evaluate_ranges=True)

    def test_optin_npm_range_matches_own_ecosystem_only(self):
        self.sbom_data = {
            "bomFormat": "CycloneDX", "specVersion": "1.6",
            "components": [
                {"type": "library", "name": "@scope/lib", "version": "2.3.4",
                 "purl": "pkg:npm/%40scope/lib@2.3.4"},
                {"type": "library", "name": "@scope/lib", "version": "2.3.5",
                 "purl": "pkg:npm/%40scope/lib@2.3.5"},
            ],
        }
        self.osv_data = {"vulns": [
            {
                "id": "CVE-2026-12345",
                "affected": [
                    {
                        "package": {"name": "@scope/lib", "ecosystem": "npm"},
                        "ranges": [
                            {
                                "type": "SEMVER",
                                "events": [
                                    {"introduced": "2.3.0", "ended": "2.3.5"}
                                ],
                            }
                        ],
                    }
                ],
            }
        ]}
        self.write()
        result = self.compare(evaluate_ranges=True, reveal=True)
        self.assertEqual(result["candidates"], [
            {"advisory_id": "CVE-2026-12345", "ecosystem": "npm",
             "name": "@scope/lib", "version": "2.3.4"},
        ])

    def test_cli_evaluate_ranges_flag(self):
        argv = ["compare-osv", "--file", str(self.sbom),
                "--osv-file", str(self.osv)]
        with redirect_stdout(StringIO()) as out:
            self.assertEqual(sbom_cli(argv), 0)
        self.assertNotIn("CVE-2026-11111", out.getvalue())
        self.assertEqual(
            json.loads(out.getvalue())["matched_advisory_package_pairs"], 0)
        with redirect_stdout(StringIO()) as out:
            self.assertEqual(
                sbom_cli(argv + ["--evaluate-ranges", "--show-candidates"]), 0)
        self.assertIn("CVE-2026-11111", out.getvalue())
        self.assertEqual(
            json.loads(out.getvalue())["matched_advisory_package_pairs"], 1)

    def test_never_opens_network_or_process_in_range_evaluation(self):
        before = (self.sbom.read_bytes(), self.osv.read_bytes())
        with (patch("socket.create_connection",
                    side_effect=AssertionError("unexpected network")),
              patch("subprocess.run",
                    side_effect=AssertionError("unexpected executable")),
              patch("urllib.request.urlopen",
                    side_effect=AssertionError("unexpected HTTP"))):
            self.compare(evaluate_ranges=True)
        self.assertEqual(before, (self.sbom.read_bytes(), self.osv.read_bytes()))


if __name__ == "__main__":
    unittest.main()
