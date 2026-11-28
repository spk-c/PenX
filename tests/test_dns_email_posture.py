"""PX-303: read-only DNS/email-domain posture report.

Hand-authored synthetic resolver answers (tests/fixtures/scanner_corpus/
dns_email_posture_v1.json) are replayed through the real dns_email_posture
function with a mocked resolver. No live resolver traffic: socket, subprocess
and requests I/O are guarded.
"""
from __future__ import annotations

from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import dns.exception
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.resolver

from penx_app.scanners.passive_recon import dns_email_posture
from penx_app.scanners.scanner_targets import normalize_host

FIXTURE = Path(__file__).parent / "fixtures" / "scanner_corpus" / "dns_email_posture_v1.json"
RECORD_TYPES = ("mx", "spf", "dmarc", "mta_sts", "caa", "dkim", "dnssec")


def _build_rdata(rrtype, entry):
    """Fixture entries are either text forms or wire-string TXT payloads."""
    rdtype = dns.rdatatype.from_text(rrtype)
    if isinstance(entry, dict):
        wire = b"".join(bytes([len(s)]) + s.encode("ascii") for s in entry["txt"])
        return dns.rdata.from_wire(dns.rdataclass.IN, rdtype, wire, 0, len(wire))
    return dns.rdata.from_text(dns.rdataclass.IN, rdtype, entry)


class DnsEmailPostureTests(unittest.TestCase):
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
        assert corpus["schema"] == "penx-dns-email-posture-v1"
        assert corpus["provenance"]["kind"] == "hand-authored-synthetic"
        return corpus["cases"]

    def _run(self, case, host="example.test"):
        answers = case["answers"]
        calls = []

        def lookup(host, rrtype, *, lifetime):
            self.assertEqual(lifetime, 5)
            calls.append((host, rrtype))
            return [_build_rdata(rrtype, entry)
                    for entry in answers.get(f"{rrtype}@{host}", [])]

        with patch.object(dns.resolver, "resolve", side_effect=lookup):
            report = dns_email_posture(host, resolver=None,
                                       dkim_selectors=case["dkim_selectors"])
        return report, calls

    def test_fixture_integrity(self):
        for case in self._load_cases():
            with self.subTest(case=case["id"]):
                canonical = json.dumps(case["answers"], sort_keys=True,
                                       separators=(",", ":"))
                self.assertEqual(
                    hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
                    case["sha256"])

    def test_fixture_cases(self):
        for case in self._load_cases():
            with self.subTest(case=case["id"]):
                report, _ = self._run(case)
                expected = case["expected"]
                self.assertEqual(report["schema"], "penx-dns-email-posture-v1")
                self.assertEqual(report["host"], "example.test")
                # The report is a JSON artifact, so it must always serialize.
                self.assertEqual(json.loads(json.dumps(report))["host"], "example.test")
                for rtype in RECORD_TYPES:
                    self.assertEqual(report["records"][rtype]["state"],
                                     expected["states"][rtype],
                                     f"{case['id']} {rtype}")
                self.assertEqual(report["summary"], expected["summary"])
                for rtype, values in expected.get("values", {}).items():
                    self.assertEqual(report["records"][rtype]["values"], values)
                for rtype in RECORD_TYPES:
                    self.assertEqual(
                        report["records"][rtype]["reason"],
                        expected.get("reasons", {}).get(rtype, ""),
                        f"{case['id']} {rtype}")
                self.assertEqual(report["diagnostics"], expected["diagnostics"])

    def test_counts_are_observed_records(self):
        report, _ = self._run(next(c for c in self._load_cases()
                                   if c["id"] == "posture-complete"))
        for rtype in RECORD_TYPES:
            self.assertEqual(report["records"][rtype]["count"], 1)

    def test_no_dkim_selector_guessing(self):
        case = next(c for c in self._load_cases() if c["id"] == "posture-complete")
        _, calls = self._run(case)
        # Only the explicitly provided selector is queried; nothing is guessed.
        dkim_calls = [h for h, rt in calls if rt == "TXT" and "_domainkey" in h]
        self.assertEqual(dkim_calls, ["default._domainkey.example.test"])

    def test_nxdomain_all_missing(self):
        def lookup(host, rrtype, *, lifetime):
            raise dns.resolver.NXDOMAIN()
        with patch.object(dns.resolver, "resolve", side_effect=lookup):
            report = dns_email_posture("example.test")
        for rtype in RECORD_TYPES:
            self.assertEqual(report["records"][rtype]["state"], "missing")
        self.assertEqual(report["summary"]["missing"], 7)
        self.assertFalse(report["summary"]["evidence"])
        self.assertEqual(report["records"]["spf"]["reason"], "no record")

    def test_resolver_error_is_missing_not_unverified(self):
        def lookup(host, rrtype, *, lifetime):
            raise dns.exception.Timeout()
        with patch.object(dns.resolver, "resolve", side_effect=lookup):
            report = dns_email_posture("example.test")
        for rtype in RECORD_TYPES:
            self.assertEqual(report["records"][rtype]["state"], "missing")
        self.assertEqual(report["records"]["mx"]["reason"], "resolver error (Timeout)")

    def test_idn_host_is_idna_encoded(self):
        normalized = normalize_host("bücher.example.test")

        def lookup(host, rrtype, *, lifetime):
            self.assertTrue(all(c.isascii() for c in host))
            if rrtype == "TXT" and host == normalized:
                return [dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.TXT,
                                             '"v=spf1 ~all"')]
            return []

        with patch.object(dns.resolver, "resolve", side_effect=lookup):
            report = dns_email_posture("bücher.example.test")
        self.assertEqual(report["host"], normalized)
        self.assertEqual(report["records"]["spf"]["state"],
                         "configured-but-unverified")

    def test_wildcard_host_rejected(self):
        with self.assertRaises(ValueError):
            dns_email_posture("*.example.test")


if __name__ == "__main__":
    unittest.main()
