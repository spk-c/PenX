"""Offline contracts for the PX-005 release supply-chain transparency baseline.

Covers deterministic SBOM/manifest generation, lock file parsing edge
cases, offline bundle verification with tampered asset/hash refusal, and
the release-workflow wiring. No network, no subprocess scanners.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import release_supply_chain as rsc  # noqa: E402

from penx_app.version import VERSION  # noqa: E402

COMMIT = "a" * 40
ASSET_NAMES = (
    "PenX-Windows-x64.zip",
    "PenX-Setup-x64.exe",
    f"PenX-Linux-x86_64.tar.gz",
    f"penx_{VERSION}_amd64.deb",
)
WINDOWS_ASSETS = ["PenX-Windows-x64.zip", "PenX-Setup-x64.exe"]
LINUX_ASSETS = [name for name in ASSET_NAMES
                if name not in WINDOWS_ASSETS]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_bundle(directory: Path) -> dict:
    """Create a synthetic but structurally real release bundle."""
    (directory / "linux-assets").mkdir(parents=True)
    assets = {}
    for name in ASSET_NAMES:
        target = directory / ("linux-assets" if name in LINUX_ASSETS else ".")
        target = target / name
        target.write_bytes(b"asset-bytes:" + name.encode())
        assets[name] = target
    sbom = directory / rsc.SBOM_NAME
    rsc.generate_sbom(sbom, ROOT / "requirements.lock.txt",
                      ROOT / "requirements-build.txt")
    manifest = directory / rsc.MANIFEST_NAME
    rsc.generate_manifest(manifest, sbom, list(assets.values()),
                          commit=COMMIT, event="push",
                          ref="v" + VERSION, repository="spk-c/PenX",
                          python_version="3.13")

    def sums(names):
        return "".join(f"{_sha256(assets[n])}  {n}\n" for n in sorted(names))

    (directory / "SHA256SUMS.txt").write_text(sums(WINDOWS_ASSETS),
                                             encoding="ascii")
    (directory / "linux-assets" / "SHA256SUMS-Linux.txt").write_text(
        sums(LINUX_ASSETS), encoding="ascii")
    return assets


def _failures(findings) -> list:
    return [message for level, message in findings if level == "FAIL"]


class SbomGenerationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = self.tmpdir = None
        import tempfile
        self._tmp = tempfile.TemporaryDirectory(prefix="penx-sbom-")
        self.tmp = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def _document(self) -> dict:
        output = self.tmp / "sbom.json"
        rsc.generate_sbom(output, ROOT / "requirements.lock.txt",
                          ROOT / "requirements-build.txt")
        return json.loads(output.read_text(encoding="utf-8"))

    def test_sbom_is_byte_deterministic(self):
        first = self.tmp / "a.json"
        second = self.tmp / "b.json"
        rsc.generate_sbom(first, ROOT / "requirements.lock.txt",
                          ROOT / "requirements-build.txt")
        rsc.generate_sbom(second, ROOT / "requirements.lock.txt",
                          ROOT / "requirements-build.txt")
        self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_sbom_covers_exactly_the_locked_runtime_packages(self):
        document = self._document()
        runtime = {
            (c["name"].lower(), c["version"])
            for c in document["components"]
            if c["properties"][0]["value"] == "runtime"
        }
        locked = {(n.lower(), v) for n, v, _ in
                  rsc.parse_locked_requirements(ROOT / "requirements.lock.txt")}
        self.assertEqual(runtime, locked)
        self.assertTrue(locked, "Lock file must not be empty")

    def test_sbom_runtime_components_carry_purl_and_sorted_hashes(self):
        document = self._document()
        locked = {n.lower(): (n, v, hashes)
                  for n, v, hashes in
                  rsc.parse_locked_requirements(
                      ROOT / "requirements.lock.txt")}
        for component in document["components"]:
            if component["properties"][0]["value"] != "runtime":
                continue
            name = component["name"].lower()
            expected_name, expected_version, expected_hashes = locked[name]
            self.assertEqual(component["version"], expected_version)
            self.assertEqual(
                component["purl"],
                f"pkg:pypi/{expected_name.lower()}@{expected_version}")
            self.assertEqual(
                [h["value"] for h in component["hashes"]],
                sorted(expected_hashes))
            self.assertTrue(all(h["alg"] == "sha256"
                                for h in component["hashes"]))

    def test_sbom_marks_build_dependencies_without_versions(self):
        document = self._document()
        build = rsc.parse_build_requirements(ROOT / "requirements-build.txt")
        build_components = [
            c for c in document["components"]
            if c["properties"][0]["value"] == "build"
        ]
        self.assertEqual({c["name"] for c in build_components},
                         {name for name, _ in build})
        for component in build_components:
            self.assertNotIn("version", component)
            declared = {p["name"]: p["value"] for p in component["properties"]}
            self.assertIn("penx:declared", declared)

    def test_sbom_has_no_nondeterministic_fields(self):
        document = self._document()
        self.assertNotIn("serialNumber", document)
        self.assertNotIn("timestamp", document["metadata"])
        self.assertEqual(document["bomFormat"], "CycloneDX")
        self.assertEqual(document["specVersion"], "1.5")

    def test_sbom_metadata_component_identifies_penx(self):
        document = self._document()
        component = document["metadata"]["component"]
        self.assertEqual(component["name"], "penx")
        self.assertEqual(component["version"], VERSION)
        self.assertEqual(component["purl"],
                         f"pkg:github/spk-c/PenX@v{VERSION}")


class LockfileParserTests(unittest.TestCase):
    def test_lockfile_parser_handles_continuations_and_comments(self):
        import tempfile
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            lock = tmp / "lock.txt"
            lock.write_text(
                "# header comment\n"
                "\n"
                "alpha==1.0.0 \\\n"
                "    --hash=sha256:" + "1" * 64 + " \\\n"
                "    --hash=sha256:" + "2" * 64 + "\n"
                "    # via\n"
                "    #   alpha\n"
                "beta==2.0\n",
                encoding="utf-8")
            result = rsc.parse_locked_requirements(lock)
        self.assertEqual(
            result,
            [("alpha", "1.0.0", ("1" * 64, "2" * 64)), ("beta", "2.0", ())])

    def test_lockfile_parser_rejects_hash_before_package(self):
        import tempfile
        with tempfile.TemporaryDirectory() as raw:
            lock = Path(raw) / "lock.txt"
            lock.write_text("--hash=sha256:" + "1" * 64 + "\n",
                            encoding="utf-8")
            with self.assertRaises(ValueError):
                rsc.parse_locked_requirements(lock)

    def test_lockfile_parser_rejects_unknown_line(self):
        import tempfile
        with tempfile.TemporaryDirectory() as raw:
            lock = Path(raw) / "lock.txt"
            lock.write_text("not-a-package line\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                rsc.parse_locked_requirements(lock)

    def test_build_requirements_parser(self):
        import tempfile
        with tempfile.TemporaryDirectory() as raw:
            build = Path(raw) / "build.txt"
            build.write_text(
                "# comment\npyinstaller>=6.15,<7\nwheel\n", encoding="utf-8")
            self.assertEqual(
                rsc.parse_build_requirements(build),
                [("pyinstaller", ">=6.15,<7"), ("wheel", "")])

    def test_sha256sums_parser(self):
        import tempfile
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw) / "sums.txt"
            tmp.write_text(
                "1" * 64 + "  a.zip\n" + "2" * 64 + "  b.exe\n",
                encoding="ascii")
            self.assertEqual(
                rsc.parse_sha256sums(tmp), {"a.zip": "1" * 64, "b.exe": "2" * 64})
            tmp.write_text("1" * 64 + " a.zip\n", encoding="ascii")
            with self.assertRaises(ValueError):
                rsc.parse_sha256sums(tmp)
            tmp.write_text("1" * 64 + "  a.zip\n" + "2" * 64 + "  a.zip\n",
                           encoding="ascii")
            with self.assertRaises(ValueError):
                rsc.parse_sha256sums(tmp)
            tmp.write_text("1" * 63 + "  a.zip\n", encoding="ascii")
            with self.assertRaises(ValueError):
                rsc.parse_sha256sums(tmp)


class ManifestTests(unittest.TestCase):
    def test_manifest_is_byte_deterministic(self):
        import tempfile
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            assets = _write_bundle(tmp)
            first = tmp / "m1.json"
            second = tmp / "m2.json"
            rsc.generate_manifest(first, tmp / rsc.SBOM_NAME,
                                  list(assets.values()),
                                  commit=COMMIT, event="push",
                                  ref="v" + VERSION,
                                  repository="spk-c/PenX",
                                  python_version="3.13")
            rsc.generate_manifest(second, tmp / rsc.SBOM_NAME,
                                  list(assets.values()),
                                  commit=COMMIT, event="push",
                                  ref="v" + VERSION,
                                  repository="spk-c/PenX",
                                  python_version="3.13")
            self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_manifest_records_release_facts(self):
        import tempfile
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            assets = _write_bundle(tmp)
            manifest = json.loads(
                (tmp / rsc.MANIFEST_NAME).read_text(encoding="utf-8"))
            self.assertEqual(manifest["manifest"], rsc.MANIFEST_ID)
            self.assertEqual(manifest["version"], VERSION)
            self.assertEqual(manifest["commit"], COMMIT)
            self.assertEqual(manifest["ref"], "v" + VERSION)
            self.assertEqual(manifest["event"], "push")
            self.assertEqual(manifest["repository"], "spk-c/PenX")
            self.assertEqual(manifest["build_workflow"], rsc.BUILD_WORKFLOW)
            self.assertEqual(manifest["signing"]["scheme"], "none")
            self.assertEqual(
                manifest["sbom"],
                {"file": rsc.SBOM_NAME, "format": rsc.SBOM_FORMAT,
                 "sha256": _sha256(tmp / rsc.SBOM_NAME)})
            names = [a["name"] for a in manifest["assets"]]
            self.assertEqual(names, sorted(ASSET_NAMES))
            for entry in manifest["assets"]:
                self.assertEqual(entry["sha256"],
                                 _sha256(assets[entry["name"]]))
                self.assertEqual(
                    entry["platform"],
                    rsc.platform_for_asset(entry["name"]))

    def test_generate_manifest_rejects_bad_commit(self):
        import tempfile
        with tempfile.TemporaryDirectory() as raw:
            tmp = Path(raw)
            assets = _write_bundle(tmp)
            with self.assertRaises(ValueError):
                rsc.generate_manifest(tmp / "m.json", tmp / rsc.SBOM_NAME,
                                      list(assets.values()), commit="short",
                                      event="push", ref="v" + VERSION,
                                      repository="spk-c/PenX",
                                      python_version="3.13")

    def test_platform_for_asset(self):
        self.assertEqual(rsc.platform_for_asset("PenX-Windows-x64.zip"),
                         "windows-x64")
        self.assertEqual(rsc.platform_for_asset("PenX-Setup-x64.exe"),
                         "windows-x64")
        self.assertEqual(
            rsc.platform_for_asset("PenX-Linux-x86_64.tar.gz"), "linux-x86_64")
        self.assertEqual(
            rsc.platform_for_asset(f"penx_{VERSION}_amd64.deb"),
            "linux-amd64")
        with self.assertRaises(ValueError):
            rsc.platform_for_asset("unknown.zip")


class VerifyBundleTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        self._tmp = tempfile.TemporaryDirectory(prefix="penx-verify-")
        self.bundle = Path(self._tmp.name)
        self.assets = _write_bundle(self.bundle)

    def tearDown(self):
        self._tmp.cleanup()

    def _verify(self, **kwargs):
        return rsc.verify_release(self.bundle, **kwargs)

    def test_intact_bundle_passes(self):
        findings = self._verify(expect_version=VERSION, expect_commit=COMMIT)
        self.assertTrue(findings, "Verification must produce checks")
        self.assertEqual(_failures(findings), [])

    def test_tampered_asset_is_refused(self):
        path = self.assets["PenX-Windows-x64.zip"]
        data = path.read_bytes()
        path.write_bytes(data[:-1] + bytes([data[-1] ^ 0xFF]))
        failures = _failures(self._verify())
        self.assertTrue(any("PenX-Windows-x64.zip" in m
                            and "SHA256" in m for m in failures), failures)

    def test_tampered_sbom_is_refused(self):
        sbom = self.bundle / rsc.SBOM_NAME
        sbom.write_bytes(sbom.read_bytes() + b"\n")
        failures = _failures(self._verify())
        self.assertTrue(any(rsc.SBOM_NAME in m for m in failures), failures)

    def test_missing_asset_is_refused(self):
        self.assets["penx_" + VERSION + "_amd64.deb"].unlink()
        failures = _failures(self._verify())
        self.assertTrue(any("exactly once" in m for m in failures), failures)

    def test_duplicate_asset_is_refused(self):
        extra = self.bundle / "extra" / "PenX-Windows-x64.zip"
        extra.parent.mkdir()
        extra.write_bytes(self.assets["PenX-Windows-x64.zip"].read_bytes())
        failures = _failures(self._verify())
        self.assertTrue(any("exactly once" in m for m in failures), failures)

    def test_wrong_expected_version_is_refused(self):
        failures = _failures(self._verify(expect_version="9.9.9"))
        self.assertTrue(any("matches expected '9.9.9'" in m
                            for m in failures), failures)

    def test_wrong_expected_commit_is_refused(self):
        failures = _failures(self._verify(expect_commit="b" * 40))
        self.assertTrue(any("commit" in m for m in failures), failures)

    def _mutate_manifest(self, **changes):
        path = self.bundle / rsc.MANIFEST_NAME
        manifest = json.loads(path.read_text(encoding="utf-8"))
        manifest.update(changes)
        path.write_text(json.dumps(manifest), encoding="utf-8")

    def test_malformed_commit_is_refused(self):
        self._mutate_manifest(commit="nope")
        failures = _failures(self._verify())
        self.assertTrue(any("40-character" in m for m in failures), failures)

    def test_ref_mismatch_on_push_is_refused(self):
        self._mutate_manifest(ref="main")
        failures = _failures(self._verify())
        self.assertTrue(any("ref" in m.lower() for m in failures), failures)

    def test_non_push_event_allows_branch_ref(self):
        self._mutate_manifest(event="workflow_dispatch", ref="feature/x")
        self.assertEqual(_failures(self._verify()), [])

    def test_missing_manifest_is_refused(self):
        (self.bundle / rsc.MANIFEST_NAME).unlink()
        findings = self._verify()
        self.assertEqual([level for level, _ in findings], ["FAIL"])

    def test_unreadable_manifest_is_refused(self):
        (self.bundle / rsc.MANIFEST_NAME).write_text("not json",
                                                     encoding="utf-8")
        findings = self._verify()
        self.assertEqual(_failures(findings), findings.__class__([
            m for _, m in findings]))
        self.assertTrue(any("Unreadable" in m for m in _failures(findings)))

    def test_wrong_sha256sums_digest_is_refused(self):
        sums = self.bundle / "SHA256SUMS.txt"
        text = sums.read_text(encoding="ascii")
        replacement = ("0" * 64 if text.split()[0] != "0" * 64
                       else "1" * 64)
        sums.write_text(text.replace(text.split()[0], replacement, 1),
                        encoding="ascii")
        failures = _failures(self._verify())
        self.assertTrue(any("SHA256SUMS.txt digest" in m
                            for m in failures), failures)

    def test_missing_linux_summaries_are_refused(self):
        (self.bundle / "linux-assets" / "SHA256SUMS-Linux.txt").unlink()
        failures = _failures(self._verify())
        self.assertTrue(any("SHA256SUMS-Linux.txt" in m
                            for m in failures), failures)


class ReleaseWorkflowTests(unittest.TestCase):
    def test_release_workflow_generates_publishes_and_verifies_bundle(self):
        workflow = (ROOT / ".github" / "workflows" / "release.yml"
                    ).read_text(encoding="utf-8")
        for phrase in (
            "python release_supply_chain.py sbom --output "
            "release-bundle/PenX-SBOM.json",
            "python release_supply_chain.py manifest "
            "--output release-bundle/PenX-BUILD-MANIFEST.json",
            "python release_supply_chain.py verify-release release-bundle",
            "release-bundle/PenX-SBOM.json release-bundle/"
            "PenX-BUILD-MANIFEST.json --verify-tag",
        ):
            self.assertIn(phrase, workflow)

    def test_release_cli_help_runs_offline(self):
        proc = subprocess.run(
            [sys.executable, str(ROOT / "release_supply_chain.py"), "--help"],
            cwd=ROOT, text=True, capture_output=True, timeout=30)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        for command in ("sbom", "manifest", "verify-release"):
            self.assertIn(command, proc.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
