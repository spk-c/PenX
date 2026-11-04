"""PX-304 untrusted SBOM offline parser boundary tests."""
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
from penx_app.intelligence import sbom_inventory as si


class OfflineSBOMTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="penx-sbom-")
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "inventory.json"
        self.cyclonedx = {
            "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "components": [
                {"type": "library", "name": "Django", "version": "5.1.0",
                 "purl": "pkg:pypi/Django@5.1.0"},
                {"type": "library", "name": "lib", "version": "1.2.3",
                 "purl": "pkg:npm/%40scope/lib@1.2.3"},
                {"type": "library", "name": "opaque-custom-lib", "version": "2026",
                 "purl": "pkg:maven/example.org/opaque-custom-lib@2026"},
                {"type": "library", "name": "missing-origin", "version": "1.0"},
            ],
        }
        self.write(self.cyclonedx)

    def write(self, data):
        self.path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")

    def inspect(self, *, reveal=False):
        return si.inspect_sbom(self.path, include_identities=reveal)

    def test_cyclonedx_16_strict_exact_identities_and_redaction(self):
        report = self.inspect()
        self.assertEqual(report["schema"], "penx-sbom-inventory-v1")
        self.assertEqual(report["source_format"], "CycloneDX")
        self.assertEqual(report["exact_package_identities"], 2)
        self.assertEqual(report["unresolved_components"], 2)
        self.assertEqual(report["total_components"], 4)
        self.assertEqual(report["ecosystems"], {"PyPI": 1, "npm": 1})
        self.assertIsNone(report["identities"])
        self.assertTrue(report["identities_redacted"])
        self.assertFalse(report["vulnerability_verified"])
        self.assertFalse(report["network_access"])
        self.assertNotIn("Django", json.dumps(report))

    def test_cyclonedx_15_and_explicit_disclosure(self):
        self.cyclonedx["specVersion"] = "1.5"
        self.write(self.cyclonedx)
        report = self.inspect(reveal=True)
        self.assertFalse(report["identities_redacted"])
        self.assertEqual(report["identities"], [
            {"ecosystem": "PyPI", "name": "django", "version": "5.1.0"},
            {"ecosystem": "npm", "name": "@scope/lib", "version": "1.2.3"},
        ])
        self.assertFalse(report["vulnerability_verified"])

    def test_spdx23_purl_and_bounded_unresolved_count(self):
        data = {
            "spdxVersion": "SPDX-2.3",
            "SPDXID": "SPDXRef-DOCUMENT",
            "packages": [
                {"name": "django", "versionInfo": "5.1.0",
                 "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER",
                                   "referenceType": "purl",
                                   "referenceLocator": "pkg:pypi/django@5.1.0"}]},
                {"name": "not-attributable", "versionInfo": "2.0",
                 "externalRefs": []},
            ],
        }
        self.write(data)
        report = self.inspect(reveal=True)
        self.assertEqual(report["source_format"], "SPDX-2.3")
        self.assertEqual(report["exact_package_identities"], 1)
        self.assertEqual(report["unresolved_components"], 1)
        self.assertEqual(report["identities"][0]["name"], "django")

    def test_spdx_two_purls_and_duplicate_exact_identity_rejected(self):
        data = {
            "spdxVersion": "SPDX-2.3",
            "packages": [
                {"name": "django", "versionInfo": "5.1.0",
                 "externalRefs": [
                     {"referenceType": "purl",
                      "referenceLocator": "pkg:pypi/django@5.1.0"},
                     {"referenceType": "purl",
                      "referenceLocator": "pkg:pypi/django@5.1.0"}]},
            ],
        }
        self.write(data)
        with self.assertRaises(si.SBOMError):
            self.inspect()
        self.cyclonedx["components"].append(self.cyclonedx["components"][0])
        self.write(self.cyclonedx)
        with self.assertRaisesRegex(si.SBOMError, "Duplicate"):
            self.inspect()

    def test_ambiguous_versions_and_qualifiers_not_matched(self):
        self.cyclonedx["components"] = [
            {"name": "Django", "version": "5.1.1",
             "purl": "pkg:pypi/Django@5.1.0"},
            {"name": "Django", "version": "5.1.0",
             "purl": "pkg:pypi/Django@5.1.0?repository_url=private"},
            {"name": "Django", "version": "5.1.0",
             "purl": "pkg:pypi/Django@5.1.0#download"},
            {"name": "Django", "version": "5.1.0",
             "purl": "pkg:pypi/%2e%2e%2fDjango@5.1.0"},
        ]
        self.write(self.cyclonedx)
        report = self.inspect()
        self.assertEqual(report["exact_package_identities"], 0)
        self.assertEqual(report["unresolved_components"], 4)
        self.assertFalse(report["vulnerability_verified"])

    def test_corrupted_and_conflicting_json_fail_closed(self):
        invalid = [
            b'{"bomFormat":"CycloneDX","bomFormat":"SPDX","specVersion":"1.6","components":[]}',
            b'{"bomFormat":"CycloneDX","specVersion":"1.6","components":{}}',
            b'{"bomFormat":"CycloneDX","specVersion":"2.0","components":[]}',
            b'{"spdxVersion":"SPDX-3.0","packages":[]}',
            b'{"bomFormat":"CycloneDX","specVersion":"1.6","components":NaN}',
            b'\xff',
            b'[]',
            b'',
        ]
        for raw in invalid:
            with self.subTest(raw=raw):
                self.path.write_bytes(raw)
                with self.assertRaises((si.SBOMError, ValueError)):
                    self.inspect()

    def test_unsafe_component_data_and_percent_escapes(self):
        for value in ("injected\nname", "a" * 161, ""):
            with self.subTest(name=value):
                self.cyclonedx["components"][0]["name"] = value
                self.write(self.cyclonedx)
                with self.assertRaises(si.SBOMError):
                    self.inspect()
        self.cyclonedx["components"][0]["name"] = "Django"
        self.cyclonedx["components"][0]["purl"] = "pkg:pypi/%ZZ@5.1.0"
        self.write(self.cyclonedx)
        with self.assertRaises(si.SBOMError):
            self.inspect()

    def test_input_caps_and_symlink_fail_closed(self):
        self.cyclonedx["components"] = [
            {"name": "lib", "version": "1"} for _ in range(si.MAX_COMPONENTS + 1)
        ]
        self.write(self.cyclonedx)
        with self.assertRaisesRegex(si.SBOMError, "limit"):
            self.inspect()
        self.path.write_bytes(b"a" * (si.MAX_FILE_BYTES + 1))
        with self.assertRaisesRegex(si.SBOMError, "size"):
            self.inspect()
        real = self.path.with_name("actual.json")
        self.path.rename(real)
        try:
            self.path.symlink_to(real)
        except (NotImplementedError, OSError):
            self.skipTest("symlink unavailable")
        with self.assertRaises((ValueError, OSError)):
            self.inspect()

    def test_cli_generic_failure_redaction_and_explicit_identity_output(self):
        with redirect_stdout(StringIO()) as out:
            self.assertEqual(sbom_cli(["inspect", "--file", str(self.path)]), 0)
        data = json.loads(out.getvalue())
        self.assertIsNone(data["identities"])
        self.assertNotIn("django", out.getvalue().lower())
        with redirect_stdout(StringIO()) as out:
            self.assertEqual(sbom_cli([
                "inspect", "--file", str(self.path), "--show-identities"]), 0)
        self.assertIn("django", out.getvalue().lower())
        self.path.write_bytes(b"password=super-secret")
        with redirect_stdout(StringIO()) as out:
            self.assertEqual(sbom_cli(["inspect", "--file", str(self.path)]), 2)
        self.assertNotIn("super-secret", out.getvalue())
        self.assertEqual(json.loads(out.getvalue())["status"], "unverified")

    def test_no_network_process_or_provider_and_no_file_changes(self):
        before = self.path.read_bytes()
        with (patch("socket.create_connection",
                    side_effect=AssertionError("unexpected network")),
              patch("subprocess.run",
                    side_effect=AssertionError("unexpected executable")),
              patch("urllib.request.urlopen",
                    side_effect=AssertionError("unexpected outbound lookup"))):
            report = self.inspect()
        self.assertEqual(before, self.path.read_bytes())
        self.assertFalse(report["network_access"])

    def test_bootstrap_dispatch_is_noninteractive(self):
        with patch("sys.argv", ["penx.py", "sbom", "inspect",
                                "--file", str(self.path)]), \
             redirect_stdout(StringIO()) as out:
            self.assertEqual(bootstrap_main(), 0)
        self.assertEqual(json.loads(out.getvalue())["total_components"], 4)


if __name__ == "__main__":
    unittest.main()
