"""PX-003 per-adapter stdout proof: offline only, no network targets."""
from __future__ import annotations

from contextlib import redirect_stdout
from dataclasses import replace
from io import StringIO
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from penx_app.application.headless_scan import main as headless_main
from penx_app.application.scan_profiles import build_custom_plan
from penx_app.application.scan_planner import run_plan
from penx_app.domain.scan_models import ScanResult, ScannerOutput
from penx_app.scanners.process_runner import run_tool
from penx_app.storage.raw_artifacts import retain_artifacts, revalidate_retained_evidence
from penx_app.application.evidence_verification import verify_metadata_file


def fixture_command(content: bytes = b"80/tcp open http\r\n") -> list[str]:
    return [sys.executable, "-c",
            "import sys;sys.stdout.buffer.write(" + repr(content) + ")"]


def one_process(_target: str) -> ScannerOutput:
    return run_tool(fixture_command())


def altered(_target: str) -> ScannerOutput:
    output = run_tool(fixture_command())
    return ScannerOutput("[NMAP SUMMARY]\n" + str(output),
                         status=output.status, evidence=output.evidence)


def two_processes(_target: str) -> ScannerOutput:
    first = run_tool(fixture_command(b"first\n"))
    second = run_tool(fixture_command(b"second\n"))
    return ScannerOutput(str(second), status=second.status,
                         evidence=second.evidence)


class ScannerSessionByteProvenanceTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.raw = self.root / "raw"
        self.plan = build_custom_plan("example.test", ("1",), active_consent=False)

    def execute(self, adapter=one_process):
        return run_plan(self.plan, menu={"1": ("Nmap", adapter)},
                        stdout_bytes_directory=self.raw)

    def test_single_exact_subprocess_persists_ref_with_adapter_id(self):
        result = self.execute()
        self.assertEqual(len(result.results), 1)
        row = result.results[0]
        self.assertEqual(row.scanner_id, "nmap")
        self.assertEqual(row.status, "COMPLETE")
        self.assertIsNotNone(row.stdout_capture)
        self.assertEqual((self.raw / row.stdout_capture.filename).read_bytes(),
                         b"80/tcp open http\r\n")
        retained = retain_artifacts(result, self.raw)
        metadata = retained.metadata()
        loaded = ScanResult.from_metadata(metadata)
        self.assertEqual(loaded.results[0].stdout_capture, row.stdout_capture)
        self.assertEqual(loaded.results[0].scanner_id, "nmap")
        self.assertEqual(loaded.results[0].status, "COMPLETE")
        self.assertEqual(len(revalidate_retained_evidence(loaded, self.raw)), 1)
        manifest = self.root / "metadata.json"
        manifest.write_text(metadata, encoding="utf-8")
        report = verify_metadata_file(manifest, self.raw)
        self.assertEqual(report["stdout_byte_sources_verified"], 1)
        self.assertEqual(report["raw_sources_verified"], 1)

    def test_transformed_scanner_result_does_not_claim_stdout_bytes(self):
        result = self.execute(altered)
        self.assertIsNone(result.results[0].stdout_capture)
        self.assertEqual(list(self.raw.iterdir()) if self.raw.exists() else [], [])

    def test_two_subprocesses_are_ambiguous_and_not_attested(self):
        result = self.execute(two_processes)
        self.assertIsNone(result.results[0].stdout_capture)
        self.assertEqual(list(self.raw.iterdir()) if self.raw.exists() else [], [])

    def test_default_scan_never_retain_stdout_bytes(self):
        with patch("penx_app.storage.stdout_bytes.publish_unique",
                   side_effect=AssertionError("capture not requested")):
            result = run_plan(self.plan, menu={"1": ("Nmap", one_process)})
        self.assertIsNone(result.results[0].stdout_capture)

    def test_metadata_rejects_forged_ref_wrong_status_and_newer_versions(self):
        result = self.execute()
        serialized = json.loads(result.metadata())
        self.assertEqual(serialized["version"], 3)
        row = serialized["adapters"][0]
        for key, value in (("size_bytes", -1), ("validator", "fake"),
                           ("filename", "../stolen.bin")):
            forged = json.loads(result.metadata())
            forged["adapters"][0]["stdout_capture"][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                ScanResult.from_metadata(json.dumps(forged))
        for version in (1, 2):
            forged = json.loads(result.metadata())
            forged["version"] = version
            with self.subTest(version=version), self.assertRaises(ValueError):
                ScanResult.from_metadata(json.dumps(forged))
        bad = json.loads(result.metadata())
        bad["adapters"][0]["status"] = "PARTIAL"
        with self.assertRaises(ValueError):
            ScanResult.from_metadata(json.dumps(bad))

    def test_metadata_forged_adapter_binding_fails_offline_verification(self):
        result = self.execute()
        retained = retain_artifacts(result, self.raw)
        raw = json.loads(retained.metadata())
        raw["adapters"][0]["stdout_capture"]["text_sha256"] = "0" * 64
        manifest = self.root / "forged.json"
        manifest.write_text(json.dumps(raw), encoding="utf-8")
        with self.assertRaises(ValueError):
            verify_metadata_file(manifest, self.raw)

    def test_missing_raw_stdout_file_fails_closed(self):
        result = retain_artifacts(self.execute(), self.raw)
        manifest = self.root / "metadata.json"
        manifest.write_text(result.metadata(), encoding="utf-8")
        (self.raw / result.results[0].stdout_capture.filename).unlink()
        with self.assertRaises((OSError, ValueError)):
            verify_metadata_file(manifest, self.raw)

    def test_headless_opt_in_includes_ref_in_report_and_session_metadata(self):
        with patch("penx_app.scanners.tools.TOOLS_MENU",
                   {"1": ("Nmap", one_process)}):
            with redirect_stdout(StringIO()) as output:
                status = headless_main([
                    "--target", "example.test", "--authorized",
                    "--scanners", "1", "--raw-artifacts", str(self.raw),
                    "--output", str(self.root / "reports")])
        self.assertEqual(status, 0, output.getvalue())
        reports = list((self.root / "reports").glob("*.json"))
        self.assertEqual(len(reports), 2)
        report = json.loads((self.root / "reports" / "penx_scan.json")
                            .read_text(encoding="utf-8"))
        self.assertEqual(report["adapters"][0]["id"], "nmap")
        from jsonschema import Draft202012Validator
        schema_file = Path(__file__).resolve().parents[1] / (
            "docs/schemas/penx-scan-v1.schema.json")
        Draft202012Validator(json.loads(
            schema_file.read_text(encoding="utf-8"))).validate(report)
        self.assertIsNotNone(report["adapters"][0]["stdout_capture"])
        self.assertEqual(report["adapters"][0]["stdout_capture"]["validator"],
                         "sha256-predecode-stdout-v1")
        manifest = report["provenance_manifest"]
        metadata = self.root / "reports" / manifest["metadata_file"]
        self.assertEqual(manifest["status"],
                         "stored-reference-not-revalidated")
        import hashlib
        self.assertEqual(manifest["metadata_sha256"],
                         hashlib.sha256(metadata.read_bytes().strip()).hexdigest())
        verified = verify_metadata_file(
            metadata, self.raw, report_file=self.root / "reports" / "penx_scan.json")
        self.assertEqual(verified["stdout_byte_sources_verified"], 1)
        self.assertEqual(verified["raw_sources_verified"], 1)
        self.assertTrue(verified["report_binding_verified"])
        from penx_app.application.evidence_verification import main as verify_cli
        with redirect_stdout(StringIO()) as cli_output:
            status = verify_cli(["--metadata", str(metadata),
                                 "--artifacts", str(self.raw),
                                 "--report", str(self.root / "reports" / "penx_scan.json")])
        self.assertEqual(status, 0)
        self.assertTrue(json.loads(
            cli_output.getvalue())["report_binding_verified"])
        self.assertNotIn("80/tcp open", cli_output.getvalue())

    def test_parallel_workers_keep_byte_proofs_isolated(self):
        from dataclasses import replace as dataclass_replace
        plan = dataclass_replace(
            build_custom_plan("example.test", ("1", "5"), active_consent=False),
            max_parallelism=2)
        def first(_target):
            return run_tool(fixture_command(b"nmap owned fixture\n"))
        def second(_target):
            return run_tool(fixture_command(b"dns owned fixture\n"))
        results = run_plan(plan, menu={"1": ("Nmap", first),
                                       "5": ("DNS", second)},
                           stdout_bytes_directory=self.raw)
        self.assertEqual({row.scanner_id for row in results.results},
                         {"nmap", "dns"})
        names = {row.scanner_id: row for row in results.results}
        self.assertEqual(len({names["nmap"].stdout_capture.filename,
                              names["dns"].stdout_capture.filename}), 2)
        stored = retain_artifacts(results, self.raw)
        loaded = ScanResult.from_metadata(stored.metadata())
        self.assertEqual(len(revalidate_retained_evidence(loaded, self.raw)), 2)

    def test_mutated_stored_text_ref_blocks_byte_proof(self):
        result = retain_artifacts(self.execute(), self.raw)
        manifest = self.root / "forged.json"
        record = json.loads(result.metadata())
        record["adapters"][0]["raw_artifact"]["sha256"] = "0" * 64
        manifest.write_text(json.dumps(record), encoding="utf-8")
        with self.assertRaises((ValueError, OSError)):
            verify_metadata_file(manifest, self.raw)

    def test_plain_headless_scan_produces_no_extra_manifest(self):
        with patch("penx_app.scanners.tools.TOOLS_MENU",
                   {"1": ("Nmap", one_process)}):
            with redirect_stdout(StringIO()) as output:
                status = headless_main([
                    "--target", "example.test", "--authorized",
                    "--scanners", "1",
                    "--output", str(self.root / "reports")])
        self.assertEqual(status, 0, output.getvalue())
        reports = list((self.root / "reports").glob("*.json"))
        self.assertEqual(len(reports), 1)
        self.assertNotIn("provenance_manifest",
                         json.loads(reports[0].read_text(encoding="utf-8")))

    def test_forged_report_adapter_and_manifest_fail_closed(self):
        with patch("penx_app.scanners.tools.TOOLS_MENU",
                   {"1": ("Nmap", one_process)}):
            with redirect_stdout(StringIO()):
                self.assertEqual(headless_main([
                    "--target", "example.test", "--authorized",
                    "--scanners", "1", "--raw-artifacts", str(self.raw),
                    "--output", str(self.root / "reports")]), 0)
        report_path = self.root / "reports" / "penx_scan.json"
        original = json.loads(report_path.read_text(encoding="utf-8"))
        metadata = self.root / "reports" / original["provenance_manifest"]["metadata_file"]
        for operation in ("adapter", "sha", "filename", "status",
                          "reason", "plan", "session", "dependency"):
            forged = json.loads(json.dumps(original))
            if operation == "adapter":
                forged["adapters"][0]["id"] = "dns"
            elif operation == "sha":
                forged["provenance_manifest"]["metadata_sha256"] = "0" * 64
            elif operation == "filename":
                forged["provenance_manifest"]["metadata_file"] = "wrong.json"
            elif operation == "status":
                forged["adapters"][0]["status"] = "PARTIAL"
            elif operation == "reason":
                forged["adapters"][0]["reason"] = "error"
            elif operation == "plan":
                forged["profile"]["profile_id"] = "other"
            elif operation == "session":
                forged["session"] = 123
            else:
                forged["dependencies"] = [["1", "5"]]
            report_path.write_text(json.dumps(forged), encoding="utf-8")
            with self.subTest(operation=operation), self.assertRaises(ValueError):
                verify_metadata_file(metadata, self.raw, report_file=report_path)

    def test_cross_run_report_manifest_substitution_fails(self):
        with patch("penx_app.scanners.tools.TOOLS_MENU",
                   {"1": ("Nmap", one_process)}):
            with redirect_stdout(StringIO()):
                for _ in range(2):
                    self.assertEqual(headless_main([
                        "--target", "example.test", "--authorized",
                        "--scanners", "1", "--raw-artifacts", str(self.raw),
                        "--output", str(self.root / "reports")]), 0)
        reports = sorted((self.root / "reports").glob("penx_scan*.json"))
        main = self.root / "reports" / "penx_scan.json"
        first = json.loads(main.read_text(encoding="utf-8"))
        other = self.root / "reports" / "penx_scan_metadata_001.json"
        # The metadata contents are the same for identical fixture scans,
        # but filename-specific association must still be checked.
        with self.assertRaises(ValueError):
            verify_metadata_file(other, self.raw, report_file=main)
        self.assertTrue(reports)
        self.assertEqual(verify_metadata_file(
            self.root / "reports" / first["provenance_manifest"]["metadata_file"],
            self.raw, report_file=main)["stdout_byte_sources_verified"], 1)

    def test_legacy_metadata_unchanged_without_stdout_proofs(self):
        old = ScanResult.from_metadata(
            '{"version":1,"adapters":[{"id":"nmap","name":"Nmap",'
            '"status":"COMPLETE","evidence":true}]}')
        self.assertNotIn("stdout_capture", old.metadata())
        self.assertEqual(json.loads(old.metadata())["version"], 1)


if __name__ == "__main__":
    unittest.main()
