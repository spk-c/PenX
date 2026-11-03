"""PX-003: golden corpus for bounded DNS record rendering.

Hand-authored synthetic resolver answers (tests/fixtures/scanner_corpus/
dns_records_v1.json) are replayed through the real run_dig adapter and the
passive _dns_lookup helper, then exported through the JSON report and
SARIF boundary. No live resolver traffic: socket, subprocess and requests
I/O are guarded.
"""
from __future__ import annotations

from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.resolver

from penx_app.application.headless_scan import scan_report
from penx_app.application.scan_profiles import build_custom_plan
from penx_app.application.scanner_execution import run_selected_structured
from penx_app.domain.scan_models import ScanRequest
from penx_app.reporting.machine_reports import sarif_from_report
from penx_app.scanners import tools
from penx_app.scanners.passive_recon import _dns_lookup

FIXTURE = Path(__file__).parent / "fixtures" / "scanner_corpus" / "dns_records_v1.json"
DNS_KEY = "5"
RRTYPES = ("A", "AAAA", "MX", "NS", "TXT")


def _build_rdata(rrtype, entry):
    """Fixture entries are either text forms or wire-string TXT payloads."""
    rdtype = dns.rdatatype.from_text(rrtype)
    if isinstance(entry, dict):
        wire = b"".join(bytes([len(s)]) + s.encode("ascii") for s in entry["txt"])
        return dns.rdata.from_wire(dns.rdataclass.IN, rdtype, wire, 0, len(wire))
    return dns.rdata.from_text(dns.rdataclass.IN, rdtype, entry)


def _answers(case):
    answers = {}
    for rrtype in RRTYPES:
        answers[rrtype] = [_build_rdata(rrtype, entry)
                           for entry in case["answers"].get(rrtype, [])]
    return answers


class DnsRecordCorpusTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.io_guards = [
            self.stack.enter_context(
                patch(name, side_effect=AssertionError("offline fixture I/O")))
            for name in ("socket.socket.connect", "socket.getaddrinfo",
                         "requests.Session.request", "subprocess.Popen")
        ]

    def tearDown(self):
        for guard in self.io_guards:
            guard.assert_not_called()

    @staticmethod
    def _load_cases():
        corpus = json.loads(FIXTURE.read_text(encoding="utf-8"))
        assert corpus["schema"] == "penx-dns-records-v1"
        assert corpus["provenance"]["kind"] == "hand-authored-synthetic"
        return corpus["cases"]

    def _run_dig(self, case):
        answers = _answers(case)
        calls = []

        def lookup(host, rrtype, *, lifetime):
            self.assertEqual(lifetime, 8)
            calls.append(rrtype)
            return answers[rrtype]

        with patch.object(dns.resolver, "resolve", side_effect=lookup):
            outcome = tools.run_dig("example.test")
        self.assertEqual(calls, list(RRTYPES))
        return outcome

    def _passive(self, case):
        answers = _answers(case)

        def lookup(host, rrtype, *, lifetime):
            self.assertEqual(lifetime, 5)
            return answers[rrtype]

        with patch.object(dns.resolver, "resolve", side_effect=lookup):
            return _dns_lookup("example.test")

    def test_fixture_integrity(self):
        for case in self._load_cases():
            with self.subTest(case=case["id"]):
                canonical = json.dumps(case["answers"], sort_keys=True,
                                       separators=(",", ":"))
                self.assertEqual(
                    hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
                    case["sha256"])

    def test_corpus_statuses_and_loss_notes(self):
        for case in self._load_cases():
            with self.subTest(case=case["id"]):
                outcome = self._run_dig(case)
                expected = case["expected"]
                self.assertEqual(outcome.status, expected["status"], str(outcome))
                self.assertIs(outcome.evidence, expected["evidence"])
                self.assertEqual(outcome.diagnostics, expected["diagnostics"],
                                 str(outcome))
                text = str(outcome)
                for note in expected.get("notes", []):
                    self.assertIn(note, text)
                if not expected.get("notes"):
                    self.assertNotIn("(!)", text)

    def test_rendered_values_respect_the_char_budget(self):
        for case in self._load_cases():
            with self.subTest(case=case["id"]):
                outcome = self._run_dig(case)
                for section in str(outcome).split("\n\n"):
                    for line in section.splitlines():
                        if line.startswith(("[", "(!)", "(no record)")):
                            continue
                        self.assertLessEqual(len(line), 350, line)

    def test_passive_lookup_reports_the_same_loss(self):
        for case in self._load_cases():
            passive = case.get("passive")
            if passive is None:
                continue
            with self.subTest(case=case["id"]):
                text = self._passive(case)
                for note in passive["notes"]:
                    self.assertIn(note, text)
                if not passive["notes"]:
                    self.assertNotIn("(!)", text)
                if "retained_a" in passive:
                    line = next(l for l in text.splitlines() if l.startswith("A:"))
                    self.assertEqual(len(line[3:].split("; ")),
                                     passive["retained_a"])

    def test_rendered_output_still_counts_as_evidence(self):
        for case in self._load_cases():
            with self.subTest(case=case["id"]):
                outcome = self._run_dig(case)
                self.assertTrue(tools.recon_has_evidence(
                    tools.format_recon_for_llm({"DNS": outcome})))
                if any(case["answers"].get(r) for r in RRTYPES):
                    self.assertTrue(tools.recon_has_evidence(
                        "[DNS VIA RESOLVER]\n" + self._passive(case),
                        passive_only=True))

    def test_export_preserves_status_evidence_and_diagnostics(self):
        case = next(c for c in self._load_cases()
                   if c["expected"]["diagnostics"])
        outcome = self._run_dig(case)
        result = run_selected_structured(
            ScanRequest("example.test", (DNS_KEY,)),
            menu={DNS_KEY: ("synthetic", lambda _target: outcome)})
        plan = build_custom_plan("example.test", (DNS_KEY,), active_consent=False)
        report = scan_report(plan, result)
        sarif = sarif_from_report(report)
        adapter = report["adapters"][0]
        self.assertEqual(adapter["status"], outcome.status)
        self.assertEqual(adapter["evidence"], outcome.evidence)
        self.assertEqual(adapter["diagnostics"], outcome.diagnostics)
        self.assertEqual(len(report["findings"]), 0)
        self.assertEqual(len(sarif["runs"][0]["results"]), 0)
        self.assertIn(outcome.diagnostics, json.dumps(sarif))


if __name__ == "__main__":
    unittest.main()
