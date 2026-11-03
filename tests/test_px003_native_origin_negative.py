"""PX-003: scanner JSONL must be bound to the authorized input origin.

This synthetic corpus is entirely offline. Source hashes protect fixtures;
cross-host/port/scheme outputs cannot become unreviewed vulnerability findings.
"""
from __future__ import annotations

from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from penx_app.application.headless_scan import scan_report
from penx_app.application.scan_profiles import build_custom_plan
from penx_app.application.scanner_execution import run_selected_structured
from penx_app.domain.scan_models import ScanRequest
from penx_app.reporting.machine_reports import sarif_from_report
from penx_app.scanners import tools
from penx_app.scanners.registry import SCANNERS

PACK = Path(__file__).resolve().parent / "fixtures/scanner_corpus/native_origin_negative_v1.json"


class NativeOriginNegativeCorpusTests(unittest.TestCase):
    def setUp(self):
        self.pack = json.loads(PACK.read_text(encoding="utf-8"))
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.guards = [self.stack.enter_context(
            patch(name, side_effect=AssertionError("unexpected network/process I/O")))
            for name in ("socket.socket.connect","socket.socket.connect_ex",
                         "socket.socket.sendto","socket.getaddrinfo",
                         "subprocess.Popen","requests.Session.request")]

    def tearDown(self):
        for guard in self.guards:
            guard.assert_not_called()

    def test_immutable_input_sha_and_unique_ids(self):
        self.assertEqual(self.pack["schema"], "penx-scanner-origin-corpus-v1")
        self.assertEqual(self.pack["provenance"]["kind"], "hand-authored-synthetic")
        self.assertEqual(len({case["id"] for case in self.pack["cases"]}),
                         len(self.pack["cases"]))
        self.assertGreaterEqual(len(self.pack["cases"]), 20)
        self.assertEqual({c["scanner"] for c in self.pack["cases"]},
                         {"nuclei", "httpx", "ffuf"})
        for case in self.pack["cases"]:
            with self.subTest(id=case["id"]):
                raw = "\n".join(case["stdout"])
                self.assertEqual(hashlib.sha256(raw.encode("utf-8")).hexdigest(),
                                 case["sha256"])

    def test_scope_bound_jsonl_parser_machine_report_and_sarif(self):
        keys = {spec.id:key for key,spec in SCANNERS.items()}
        for case in self.pack["cases"]:
            with self.subTest(id=case["id"]):
                scanner = case["scanner"]
                raw = "\n".join(case["stdout"])
                expected = case["expected"]
                output = tools._summarize_native_run(
                    scanner, raw, expected_origin=case["origin"])
                self.assertEqual(output.status, expected["status"])
                self.assertEqual(output.evidence, expected["evidence"])
                self.assertEqual(str(output), expected["summary"])
                key = keys[scanner]
                result = run_selected_structured(
                    ScanRequest(case["origin"], (key,), active_consent=True),
                    menu={key:(scanner,lambda _target, captured=output:captured)})
                plan = build_custom_plan(case["origin"], (key,), active_consent=True)
                report = scan_report(plan, result)
                sarif = sarif_from_report(report)["runs"][0]
                self.assertEqual([r["rule"] for r in report["findings"]],
                                 expected["rules"])
                self.assertEqual([r["ruleId"] for r in sarif["results"]],
                                 expected["rules"])
                self.assertEqual(report["adapters"][0]["status"], expected["status"])
                self.assertEqual(report["adapters"][0]["evidence"], expected["evidence"])
                self.assertEqual(bool(result.results[0].evidence_records),
                                 expected["evidence"])
                self.assertEqual(sarif["invocations"][0]["executionSuccessful"],
                                 expected["status"] == "COMPLETE")
                public = json.dumps([report,sarif,[rec.quote for rec in result.results[0].evidence_records]],
                                    ensure_ascii=False)
                for secret in case.get("must_not_publish", []):
                    self.assertNotIn(secret, public)
                for rec in result.results[0].evidence_records:
                    self.assertTrue(rec.matches(result.results[0]))

    def test_origin_identity_rejects_ambiguous_authorities(self):
        from penx_app.scanners.native_web_scanners import _same_web_origin
        root = "https://example.test"
        self.assertTrue(_same_web_origin("https://EXAMPLE.TEST.:443/index", root))
        self.assertTrue(_same_web_origin("https://example.test:443/", root))
        for denied in (
                "https://example.test../",
                "https://example.test:8443/",
                "https://example.test@another.test/",
                "https://another.test@example.test/",
                "http://example.test/",
                "//example.test/",
                "example.test",
                "https://example.test/" + chr(10) + "spoof",
                "https://example.test:invalid/",
                "https://example.test:0/",
                "https://[2001:db8::1]:443/",
        ):
            with self.subTest(denied=repr(denied)):
                self.assertFalse(_same_web_origin(denied, root))

    def test_live_native_dispatch_wires_approved_origin_into_parser(self):
        # Only fixed synthetic adapter output is returned, never a binary.
        cases={case["id"]:case for case in self.pack["cases"]}
        for scanner, identity in (("nuclei","nuclei-other-host"),
                                  ("httpx","httpx-foreign-host"),
                                  ("ffuf","ffuf-foreign-host")):
            case=cases[identity]
            with self.subTest(scanner=scanner), \
                    patch.object(tools,"find_native",return_value="mock-scanner"), \
                    patch.object(tools,"nuclei_templates",return_value=Path("synthetic-templates")), \
                    patch.object(tools,"_run_external",
                                 return_value="\n".join(case["stdout"])) as executor:
                result=tools._run_native_web_scanner(scanner,case["origin"])
            executor.assert_called_once()
            self.assertEqual(result.status,"FAILED")
            self.assertFalse(result.evidence)

