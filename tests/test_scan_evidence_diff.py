"""Offline regressions for new Qwen scan: real citations, QA, and semantic diffs."""
from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from penx_app.intelligence.source_verification import evidence_in_scan
from penx_app.analysis.assessment_quality import apply_review, reviewer_report
from penx_app.analysis.prompts import REVIEW_PROMPT
from penx_app.application.scan_trends import compare_sessions, report_text
from penx_app.analysis.structured_output import request_structured_report


META = "MetaGenerator[Elementor 4.3.5; features: additional_custom_breakpoints]"
SPF = "v=spf1 include:spf.privateemail.com ~all"
FLYING = "PoweredBy[FlyingPress]"
RAW = (
    "[ NMAP OUTPUT ]\n80/tcp open http Cloudflare http proxy\n"
    "Nmap done: 1 IP address scanned\n"
    "[ WHATWEB OUTPUT ]\nhttps://www.shirtgeklebt.net/ [200 OK] "
    + META + ", " + FLYING + "\n"
    "[ DIG OUTPUT ]\n[TXT Records]\n" + SPF + "\n"
)


def record(name, evidence, severity="low"):
    return dict(vuln_name=name, evidence=evidence, severity=severity,
                confidence="confirmed", description="Check security impact",
                port="443", service="http", fix="Verify", cve_ids=[])


def session(sl, names, raw=RAW, *, recommendation=True):
    rows = []
    for i, name in enumerate(names, 1):
        rows.append((i, sl, name, "info" if recommendation else "low",
                     "recommendation" if recommendation else "possible",
                     "", "", "A test observation"))
    return {
        "history": (sl, "shirtgeklebt.net", "2026-10-14", "active"),
        "summary": (sl, sl, raw, "Analysis", "LOW"),
        "vulns": rows, "corrections": [],
    }


class ScanQualityFollowupTests(unittest.TestCase):
    def test_source_prefix_and_literal_quotes_are_supported(self):
        self.assertTrue(evidence_in_scan('WhatWeb output: "' + META + '"', RAW))
        self.assertTrue(evidence_in_scan('TXT Records: "' + SPF + '"', RAW))
        self.assertTrue(evidence_in_scan(
            'WhatWeb output: "' + FLYING + '"', RAW))
        self.assertTrue(evidence_in_scan(
            'WhatWeb output: "' + META + '" and TXT Records: "' + SPF + '"', RAW))
        self.assertFalse(evidence_in_scan(
            'WhatWeb output: "' + FLYING + '" and advisory: '
            '"The plugin is vulnerable to authorization bypass in version 3.9.6"', RAW))
        self.assertFalse(evidence_in_scan(
            'WhatWeb output: "' + META.replace("4.3.5", "0.0.0") + '"', RAW))
        self.assertFalse(evidence_in_scan("Apparently a vulnerability exists", RAW))
        self.assertFalse(evidence_in_scan('WhatWeb output: "short"', RAW))

    def test_scan_proves_observation_not_exploitability(self):
        vulns = [
            record("Elementor version disclosure", 'WhatWeb output: "' + META + '"'),
            record("SPF softfail for email domain", 'TXT Records: "' + SPF + '"'),
            record("Possible FlyingPress missing authorization",
                   'WhatWeb output: "' + FLYING + '" and advisory: "A made-up issue"'),
            record("Confirmed security issue fixture",
                   "80/tcp open http Cloudflare http proxy", severity="medium"),
        ]
        approved, advice, rejected = apply_review(vulns, [], RAW, [])
        self.assertEqual([v["vuln_name"] for v in approved],
                         ["Confirmed security issue fixture"])
        self.assertEqual(len(advice), 3)
        self.assertFalse(rejected)
        self.assertIn("Informational observation", advice[0]["description"])
        self.assertIn("Informational observation", advice[1]["description"])
        self.assertIn("Unverified scanner evidence", advice[2]["description"])
        self.assertNotIn("Unverified scanner evidence", advice[0]["description"])

    def test_recommendation_is_not_wrong_for_absent_json_evidence_field(self):
        rec = {"vuln_name": "Strengthen HSTS policy",
               "description": "HSTS observed; investigate includeSubDomains",
               "confidence": "recommendation", "severity": "info"}
        review = reviewer_report([], [rec])
        self.assertNotIn("EVIDENCE: ", review)
        self.assertIn("No dedicated EVIDENCE field", review)
        self.assertIn("Do NOT mark a recommendation corrected merely", REVIEW_PROMPT)
        flags = [{"vuln_name": rec["vuln_name"], "verdict": "corrected",
                  "issue": "Check 1 failure because the EVIDENCE field was empty",
                  "evidence": "", "corrected": "Keep recommendation"}]
        _, advice, _ = apply_review([], [rec], RAW, flags)
        self.assertNotIn("_review_flag", advice[0])
        flags[0]["issue"] += " and the claim is unsupported"
        _, advice, _ = apply_review([], [rec], RAW, flags)
        self.assertEqual(advice[0]["_review_flag"], "corrected")

    def test_reworded_recommendations_are_persistent_not_new_and_removed(self):
        old = session(3, [
            "Verify DMARC and SPF",
            "Investigate ebay-api.shirtgeklebt.net",
            "Verify DNSSEC status",
            "Strengthen HSTS and security headers",
            "Investigate totally unrelated plugin",
        ])
        new = session(4, [
            "Review SPF and DMARC posture",
            "Separately scan ebay-api.shirtgeklebt.net",
            "Enable DNSSEC",
            "Strengthen HSTS policy",
            "Check an unrelated cache plugin",
        ])
        diff = compare_sessions(old, new)
        renames = diff["reworded_recommendations"]
        self.assertEqual(len(renames), 4, renames)
        self.assertEqual(len(diff["new_findings"]), 1)
        self.assertEqual(len(diff["not_observed_findings"]), 1)
        self.assertEqual(len(diff["persistent_findings"]), 4)
        self.assertIn("[REWORDED]", report_text(diff))

    def test_distinct_security_topics_not_merged(self):
        old = session(3, ["Review SPF and DMARC posture",
                          "Check api-a.example.test"], recommendation=False)
        new = session(4, ["Check TLS certificate chain",
                          "Check api-b.example.test"], recommendation=False)
        diff = compare_sessions(old, new)
        self.assertEqual(len(diff["new_findings"]), 2)
        self.assertEqual(len(diff["not_observed_findings"]), 2)
        self.assertEqual(diff["reworded_recommendations"], [])

    def test_spf_only_and_dmarc_only_are_distinct_topics(self):
        old = session(3, ["Review SPF policy"])
        new = session(4, ["Review DMARC enforcement"])
        diff = compare_sessions(old, new)
        self.assertEqual(len(diff["new_findings"]), 1)
        self.assertEqual(len(diff["not_observed_findings"]), 1)
        self.assertEqual(diff["reworded_recommendations"], [])

    def test_whatweb_timeout_does_not_invalidate_completed_nmap(self):
        old = session(3, [], raw=RAW + "[ WHATWEB OUTPUT ]\n[!] Timed out after 90s")
        new = session(4, [], raw=RAW)
        diff = compare_sessions(old, new)
        self.assertTrue(diff["port_comparison_reliable"])
        self.assertFalse(diff["missing_ports"])

    def test_structured_json_sees_post_nmap_evidence(self):
        long_raw = RAW.replace("Nmap done:", "verbose Nmap trace\n" * 1500 + "Nmap done:")
        data = {
            "vulnerabilities": [], "recommendations": [],
            "exploits": [], "risk_level": "LOW", "summary": "fixture"
        }
        with patch("penx_app.analysis.structured_output.complete_chat",
                   return_value=("qwen-local", json.dumps(data))) as ask:
            request_structured_report(
                long_raw, "analysis", "",
                url="http://127.0.0.1:8080/v1/chat/completions",
                models_url="http://127.0.0.1:8080/v1/models",
                model_name="qwen-local")
        question = ask.call_args.args[0][1]["content"]
        self.assertIn(META, question)
        self.assertIn(SPF, question)
        self.assertIn("WHATWEB OUTPUT", question)


if __name__ == "__main__":
    unittest.main(verbosity=2)
