"""PX-304 local OSV version-candidate matching: no network or exposure verdict."""
from __future__ import annotations

from contextlib import redirect_stdout
from io import StringIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from penx_app.application.sbom_inspection import main as sbom_cli
from penx_app.bootstrap import main as bootstrap_main
from penx_app.intelligence import osv_snapshot_match as om
from penx_app.intelligence.sbom_inventory import SBOMError


class OfflineOSVSnapshotTests(unittest.TestCase):
    def setUp(self):
        root = tempfile.TemporaryDirectory(prefix="px304-osv-offline-")
        self.addCleanup(root.cleanup)
        self.sbom = Path(root.name) / "local-sbom.json"
        self.osv = Path(root.name) / "local-osv.json"
        self.sbom_data = {
            "bomFormat": "CycloneDX", "specVersion": "1.6",
            "components": [
                {"type": "library", "name": "Django", "version": "5.1.0",
                 "purl": "pkg:pypi/Django@5.1.0"},
                {"type": "library", "name": "@scope/lib", "version": "2.3.4",
                 "purl": "pkg:npm/%40scope/lib@2.3.4"},
                {"type": "library", "name": "untrusted-source", "version": "1",
                 "purl": "pkg:maven/org.example/untrusted-source@1"},
            ],
        }
        self.osv_data = {"vulns": [
            {"id": "GHSA-abcd-efgh-ijkl", "affected": [{
                "package": {"name": "django", "ecosystem": "PyPI"},
                "versions": ["5.0.0", "5.1.0", "5.2.0"]}]},
            {"id": "CVE-2026-12345", "affected": [{
                "package": {"name": "@scope/lib", "ecosystem": "npm"},
                "versions": ["2.3.4"]}]},
            {"id": "CVE-2026-98765", "affected": [{
                "package": {"name": "django", "ecosystem": "PyPI"},
                "versions": ["4.2.0"]}]},
            {"id": "CVE-2026-11111", "affected": [{
                "package": {"name": "django", "ecosystem": "PyPI"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]}]},
        ]}
        self.write()

    def write(self):
        self.sbom.write_text(json.dumps(self.sbom_data), encoding="utf-8")
        self.osv.write_text(json.dumps(self.osv_data), encoding="utf-8")

    def compare(self, *, reveal=False):
        return om.compare_local_osv_snapshot(
            self.sbom, self.osv, include_candidates=reveal)

    def test_only_exact_listed_versions_match_not_ranges_or_other_versions(self):
        result = self.compare()
        self.assertEqual(result["schema"], om.SCHEMA)
        self.assertEqual(result["local_advisory_records"], 4)
        self.assertEqual(result["matched_advisory_package_pairs"], 2)
        self.assertEqual(result["uninterpreted_range_entries"], 1)
        self.assertEqual(result["unsupported_or_unversioned_affected_entries"], 1)
        self.assertEqual(result["sbom_unresolved_components"], 1)
        self.assertTrue(result["candidates_redacted"])
        self.assertIsNone(result["candidates"])
        for key in ("snapshot_origin_authenticated", "advisory_freshness_verified",
                    "affected_ranges_evaluated", "vendor_backports_evaluated",
                    "vulnerability_verified", "no_match_implies_safe", "network_access"):
            self.assertFalse(result[key])
        text = json.dumps(result)
        self.assertNotIn("Django", text)
        self.assertNotIn("@scope/lib", text)
        self.assertNotIn("GHSA-abcd", text)

    def test_optin_candidates_are_sorted_and_do_not_exaggerate(self):
        rows = self.compare(reveal=True)
        self.assertFalse(rows["candidates_redacted"])
        self.assertEqual(rows["candidates"], [
            {"advisory_id": "CVE-2026-12345", "ecosystem": "npm",
             "name": "@scope/lib", "version": "2.3.4"},
            {"advisory_id": "GHSA-abcd-efgh-ijkl", "ecosystem": "PyPI",
             "name": "django", "version": "5.1.0"},
        ])
        self.assertFalse(rows["vulnerability_verified"])

    def test_empty_collection_or_unmatched_versions_never_proves_safety(self):
        self.osv_data = {"vulns": []}
        self.write()
        result = self.compare()
        self.assertEqual(result["matched_advisory_package_pairs"], 0)
        self.assertFalse(result["no_match_implies_safe"])
        self.osv_data = {"vulns": [{
            "id": "CVE-2026-12345",
            "affected": [{"package": {"name": "Django", "ecosystem": "PyPI"},
                          "versions": ["1.0.0"]}],
        }]}
        self.write()
        self.assertEqual(self.compare()["matched_advisory_package_pairs"], 0)

    def test_unsupported_osv_ecosystems_do_not_cross_match(self):
        self.osv_data = {"vulns": [{
            "id": "CVE-2026-12345", "affected": [{
                "package": {"name": "django", "ecosystem": "Debian"},
                "versions": ["5.1.0"],
            }],
        }]}
        self.write()
        self.assertEqual(self.compare()["matched_advisory_package_pairs"], 0)
        self.assertEqual(
            self.compare()["unsupported_or_unversioned_affected_entries"], 1)

    def test_malformed_and_duplicate_advisory_ids_fail_closed(self):
        for candidate in ("CVE-2026-12345\nsecret", "bad id", "", None, 123):
            with self.subTest(value=candidate):
                self.osv_data = {"vulns": [{"id": candidate, "affected": []}]}
                self.write()
                with self.assertRaises(SBOMError):
                    self.compare()
        self.osv_data = {"vulns": [
            {"id": "CVE-2026-12345", "affected": []},
            {"id": "cve-2026-12345", "affected": []}]}
        self.write()
        with self.assertRaisesRegex(SBOMError, "Duplicate"):
            self.compare()

    def test_unexpected_shapes_repeated_json_keys_and_budgets(self):
        for obj in (
            [], {"vulns": {}, "unexpected": True}, {"other": []},
            {"vulns": [None]}, {"vulns": [{"id": "CVE-2026-12345"}]},
            {"vulns": [{"id": "CVE-2026-12345", "affected": {}}]},
        ):
            self.osv.write_text(json.dumps(obj), encoding="utf-8")
            with self.subTest(obj=obj), self.assertRaises(SBOMError):
                self.compare()
        self.osv.write_text(
            '{"vulns":[],"vulns":[{"id":"CVE-2026-12345","affected":[]}]}',
            encoding="utf-8")
        with self.assertRaises(SBOMError):
            self.compare()
        self.osv_data = {"vulns": [
            {"id": f"GHSA-fixture-{i:04d}", "affected": []}
            for i in range(om.MAX_ADVISORIES + 1)]}
        self.write()
        with self.assertRaisesRegex(SBOMError, "Too many"):
            self.compare()

    def test_invalid_nested_versions_and_oversize_lists_fail_closed(self):
        base = {"id": "CVE-2026-12345", "affected": [{
            "package": {"name": "django", "ecosystem": "PyPI"},
            "versions": [123],
        }]}
        for value in (123, {}, ["5.1.0\nsecret"], ["5.1.0"] * 1001):
            base["affected"][0]["versions"] = value
            self.osv_data = {"vulns": [base]}
            self.write()
            with self.subTest(value=str(value)[:20]), self.assertRaises(SBOMError):
                self.compare()
        base["affected"][0]["versions"] = ["5.1.0"]
        base["affected"][0]["ranges"] = "untrusted"
        self.write()
        with self.assertRaises(SBOMError):
            self.compare()

    def test_cli_redacts_by_default_and_reveals_only_on_optin(self):
        argv = ["compare-osv", "--file", str(self.sbom),
                "--osv-file", str(self.osv)]
        with redirect_stdout(StringIO()) as out:
            self.assertEqual(sbom_cli(argv), 0)
        info = json.loads(out.getvalue())
        self.assertEqual(info["matched_advisory_package_pairs"], 2)
        self.assertNotIn("@scope/lib", out.getvalue())
        self.assertNotIn("GHSA-abcd", out.getvalue())
        with redirect_stdout(StringIO()) as out:
            self.assertEqual(sbom_cli(argv + ["--show-candidates"]), 0)
        self.assertIn("GHSA-abcd", out.getvalue())

    def test_failed_cli_does_not_echo_snapshot_paths_or_content(self):
        self.osv.write_bytes(b"PRIVATE-SUPPLIED-OSV")
        argv = ["compare-osv", "--file", str(self.sbom),
                "--osv-file", str(self.osv)]
        with redirect_stdout(StringIO()) as out:
            self.assertEqual(sbom_cli(argv), 2)
        self.assertEqual(json.loads(out.getvalue())["status"], "unverified")
        self.assertNotIn(str(self.osv), out.getvalue())
        self.assertNotIn("PRIVATE-SUPPLIED-OSV", out.getvalue())

    def test_never_opens_network_or_process_or_writes_supplied_files(self):
        before = (self.sbom.read_bytes(), self.osv.read_bytes())
        with (patch("socket.create_connection",
                    side_effect=AssertionError("unexpected network")),
              patch("subprocess.run",
                    side_effect=AssertionError("unexpected executable")),
              patch("urllib.request.urlopen",
                    side_effect=AssertionError("unexpected HTTP"))):
            info = self.compare()
        self.assertEqual(before, (self.sbom.read_bytes(), self.osv.read_bytes()))
        self.assertFalse(info["network_access"])

    def test_bootstrap_dispatch_to_offline_compare(self):
        argv = ["penx.py", "sbom", "compare-osv", "--file", str(self.sbom),
                "--osv-file", str(self.osv)]
        with patch("sys.argv", argv), redirect_stdout(StringIO()) as out:
            self.assertEqual(bootstrap_main(), 0)
        self.assertEqual(json.loads(out.getvalue())["matched_advisory_package_pairs"], 2)


if __name__ == "__main__":
    unittest.main()
