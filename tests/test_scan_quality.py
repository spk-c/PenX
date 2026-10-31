"""Offline regressions for the first full Cloudflare/WhatWeb/Qwen PenX scan.

No HTTP requests or real security scans are issued by these tests.
"""
import unittest
from unittest.mock import patch

from penx_app.analysis import llm
from penx_app.analysis.assessment_quality import review_evidence, reviewer_report, apply_review
from penx_app.scanners.tools import run_tool_by_command


NMAP = "8080/tcp open http Cloudflare http proxy\n8443/tcp open ssl/http Cloudflare http proxy"
CERT = "Subject Alternative Name: DNS:shirtgeklebt.net, DNS:ebay-api.shirtgeklebt.net"
SPF = 'v=spf1 include:spf.privateemail.com ~all'
RAW = ("===================================\n[ NMAP OUTPUT ]\n"
       "===================================\n" + NMAP + "\n" + CERT + "\n"
       "===================================\n[ WHOIS OUTPUT ]\n"
       "===================================\nRegistrar: fixture only\n"
       "===================================\n[ DIG OUTPUT ]\n"
       "===================================\n" + SPF + "\n"
       "===================================\n[ CURL_HEADERS OUTPUT ]\n"
       "===================================\nStrict-Transport-Security: max-age=2592000\n")


def finding(name, severity, evidence):
    return {"vuln_name": name, "severity": severity, "confidence": "possible",
            "port": "443", "service": "https",
            "description": "Claim to assess", "evidence": evidence,
            "fix": "Review controls", "cve_ids": []}



class SL11CoverageAndCveTests(unittest.TestCase):
    def test_full_scan_handles_parenthesized_profiles_and_partial_output_marker(self):
        from penx_app.reporting.scan_coverage import coverage
        raw = (
            "[ NMAP OUTPUT ]\n"
            + "=" * 50 + "\n[PENX ADAPTER STATUS: COMPLETE; EVIDENCE: YES]\n"
            "22/tcp open ssh OpenSSH 8.0\n"
            "[ NIKTO (OPTIONAL) OUTPUT ]\n"
            + "=" * 50 + "\n[PENX ADAPTER STATUS: PARTIAL; EVIDENCE: NO]\n"
            "[!] Timed out after 300s\n[PARTIAL OUTPUT]\n+ /admin/: HTTP 200\n"
            "[ NUCLEI (EXPLICIT OPT-IN) OUTPUT ]\n"
            + "=" * 50 + "\n[PENX ADAPTER STATUS: PARTIAL; EVIDENCE: NO]\n"
            "[!] Timed out after 240s\n[PARTIAL OUTPUT]\n"
            "[ HTTPX / PROJECTDISCOVERY (NATIVE) OUTPUT ]\n"
            + "=" * 50 + "\n[PENX ADAPTER STATUS: COMPLETE; EVIDENCE: YES]\n"
            "HTTP 200 | https://example.test/\n"
            "[ TLS CERTIFICATE AND HANDSHAKE OUTPUT ]\n"
            + "=" * 50 + "\n[PENX ADAPTER STATUS: COMPLETE; EVIDENCE: YES]\n"
            "TLSv1.3\n"
        )
        result = coverage(raw)
        self.assertEqual(result["status"], "PARTIAL")
        self.assertEqual(result["failed"], ["NIKTO (OPTIONAL)", "NUCLEI (EXPLICIT OPT-IN)"])
        self.assertEqual(result["completed"], [
            "NMAP", "HTTPX / PROJECTDISCOVERY (NATIVE)", "TLS CERTIFICATE AND HANDSHAKE"
        ])
        from penx_app.analysis.assessment_quality import review_evidence
        reviewed = review_evidence(raw)
        self.assertIn("NIKTO (OPTIONAL) OUTPUT", reviewed)
        self.assertIn("NUCLEI (EXPLICIT OPT-IN) OUTPUT", reviewed)
        self.assertNotIn("[PARTIAL OUTPUT]\n[... evidence", reviewed)

    def test_terrapin_regresshion_identity_is_fixed_even_without_reviewer_flag(self):
        scan = "22/tcp open ssh OpenSSH 8.0 (protocol 2.0)"
        item = finding("Outdated OpenSSH version", "low", scan)
        item["description"] = (
            "OpenSSH 8.0 was reported, while regreSSHion CVE-2023-48795 "
            "is not applicable to 8.0. Verify installed packages."
        )
        approved, advice, _ = apply_review([item], [], scan, [])
        self.assertEqual(len(approved), 1)
        self.assertEqual(advice, [])
        body = approved[0]["description"]
        self.assertIn("Terrapin (CVE-2023-48795)", body)
        self.assertIn("CVE-2024-6387", body)
        self.assertNotIn("regreSSHion CVE-2023-48795", body)
        self.assertNotIn("not applicable to 8.0", body)
        self.assertIn("regreSSHion CVE-2023-48795", approved[0]["_review_original_description"])


class SL12SMTPReviewTests(unittest.TestCase):
    def test_separate_nmap_587_auth_evidence_overrides_false_missing_ehlo_review(self):
        from penx_app.analysis.assessment_quality import _nmap_smtp_587_auth_evidence
        raw = (
            "[ NMAP OUTPUT ]\n"
            "25/tcp open smtp Exim smtpd 4.99\n"
            "| smtp-commands: host, AUTH PLAIN LOGIN, STARTTLS, HELP\n"
            "465/tcp open ssl/smtp Exim smtpd 4.99\n"
            "587/tcp open smtp Exim smtpd 4.99\n"
            "| smtp-commands: host, AUTH PLAIN LOGIN, STARTTLS, HELP\n"
            "993/tcp open ssl/imap Dovecot\n"
        )
        self.assertTrue(_nmap_smtp_587_auth_evidence(raw))
        advice = [{
            "vuln_name": "SMTP plaintext AUTH advertised before STARTTLS",
            "description": "Both 25 and 587 advertise AUTH PLAIN LOGIN prior to STARTTLS.",
            "severity": "info", "confidence": "recommendation",
        }]
        flags = [{
            "vuln_name": advice[0]["vuln_name"],
            "verdict": "corrected",
            "issue": "Port 587 is open but does not clearly show separate EHLO output.",
            "corrected": "Only port 25 advertises AUTH PLAIN LOGIN.",
        }]
        _, updated, _ = apply_review([], advice, raw, flags)
        self.assertEqual(len(updated), 1)
        self.assertIn("587/tcp service block", updated[0]["description"])
        self.assertIn("not", updated[0]["description"])
        self.assertNotIn("Only port 25", updated[0]["description"])

    def test_587_absent_is_not_invented(self):
        from penx_app.analysis.assessment_quality import _nmap_smtp_587_auth_evidence
        self.assertFalse(_nmap_smtp_587_auth_evidence(
            "25/tcp open smtp\n| smtp-commands: AUTH PLAIN LOGIN STARTTLS\n"
            "587/tcp open smtp\n| smtp-commands: STARTTLS\n"
        ))


class SL13OpenSSHAndReviewTests(unittest.TestCase):
    def test_openssh_74_is_neither_regresshion_nor_ssh_agent_exposure(self):
        raw = (
            "[ NMAP OUTPUT ]\n"
            "22/tcp open ssh OpenSSH 7.4 (protocol 2.0)\n"
            "3306/tcp open mysql MySQL 5.7.44\n"
        )
        item = finding("OpenSSH 7.4 exposed with possible known authentication vulnerabilities",
                       "high", "22/tcp open ssh OpenSSH 7.4 (protocol 2.0)")
        item["port"] = "22"
        item["service"] = "ssh"
        item["description"] = ("Banner 7.4 suggests CVE-2024-6387 and CVE-2023-38408 "
                               "with unknown vendor fixes.")
        approved, advice, rejected = apply_review([item], [], raw, [])
        self.assertEqual(approved, [])
        self.assertEqual(rejected, [])
        self.assertEqual(len(advice), 1)
        self.assertEqual(advice[0]["severity"], "info")
        self.assertEqual(advice[0]["confidence"], "recommendation")
        self.assertEqual(advice[0]["_review_flag"], "reclassified")
        self.assertIn("ssh-agent/PKCS#11", advice[0]["description"])
        self.assertIn("outside the regreSSHion", advice[0]["description"])
        self.assertIn("CVE-2024-6387", advice[0]["_review_original_description"])

    def test_open_ssh_newer_version_is_not_falsely_cleared(self):
        raw = "22/tcp open ssh OpenSSH 9.2 (protocol 2.0)"
        item = finding("Possible regreSSHion CVE-2024-6387", "medium", raw)
        item["port"] = "22"
        item["service"] = "ssh"
        approved, advice, _ = apply_review([item], [], raw, [])
        self.assertEqual(len(approved), 1)
        self.assertEqual(advice, [])

    def test_review_downgrade_changes_effective_severity(self):
        raw = "443/tcp open ssl/http nginx"
        item = finding("Potential server misconfiguration", "high", raw)
        flags = [{
            "vuln_name": item["vuln_name"],
            "verdict": "downgraded",
            "corrected": "Severity MEDIUM. Verify configuration before attribution.",
            "issue": "Risk overstated"
        }]
        approved, advice, _ = apply_review([item], [], raw, flags)
        self.assertEqual(len(approved), 1)
        self.assertEqual(advice, [])
        self.assertEqual(approved[0]["severity"], "medium")
        self.assertEqual(approved[0]["_review_original_severity"], "high")
        self.assertEqual(approved[0]["_review_flag"], "downgraded")
        self.assertIn("Severity MEDIUM", approved[0]["description"])

    def test_hallucinated_ssh_claim_is_rejected_not_resurrected(self):
        raw = "22/tcp open ssh OpenSSH 7.4"
        item = finding("SSH regreSSHion CVE-2024-6387", "high", raw)
        flags = [{"vuln_name": item["vuln_name"], "verdict": "hallucination",
                  "issue": "Not supported", "corrected": ""}]
        approved, advice, rejected = apply_review([item], [], raw, flags)
        self.assertEqual(approved, [])
        self.assertEqual(advice, [])
        self.assertEqual(len(rejected), 1)


class NiktoTerminationRegressions(unittest.TestCase):
    def test_legacy_error_limit_is_partial(self):
        from penx_app.reporting.scan_coverage import coverage
        raw = ("[ NIKTO OUTPUT ]\n"
               "==============================\n"
               "- Nikto v2.6.1\n"
               "+ ERROR: *** Error limit (20) reached for host, giving up. ***\n"
               "+ Scan terminated: 21 errors and 7 items reported\n")
        state = coverage(raw)
        self.assertEqual(state["status"], "PARTIAL")
        self.assertIn("NIKTO", state["failed"])

    def test_nikto_adapter_marks_error_limit_as_partial(self):
        from unittest.mock import patch
        from penx_app.scanners import tools
        raw = ("- Nikto v2.6.1\n"
               "+ ERROR: *** Error limit (20) reached for host, giving up. ***\n"
               "+ Scan terminated: 21 errors and 7 items reported")
        with patch.object(tools, "NIKTO_PATH", ""), \
             patch.object(tools, "_executable", return_value="nikto"), \
             patch.object(tools, "run_tool", return_value=raw):
            result = tools.run_nikto("example.test")
        self.assertEqual(result.status, "PARTIAL")


class FirstCompleteScanRegressions(unittest.TestCase):

    def test_flyingpress_version_advice_is_deduplicated(self):
        records = [
            {"vuln_name": "FlyingPress theme version unconfirmed",
             "description": "Check FlyingPress theme version.",
             "severity": "info", "confidence": "recommendation"},
            {"vuln_name": "Confirm FlyingPress theme version",
             "description": "Verify FlyingPress version in WP admin.",
             "severity": "info", "confidence": "recommendation"},
        ]
        approved, advice, _ = apply_review([], records, RAW, [])
        self.assertEqual(approved, [])
        self.assertEqual(len(advice), 1)
        self.assertIn("FlyingPress plugin", advice[0]["vuln_name"])

    def test_nikto_connection_failure_is_partial(self):
        from penx_app.reporting.report_design import _scan_intelligence
        output = "[ NIKTO OUTPUT ]\\n- Nikto v2.6.1\\n+ [FAIL] Unable to connect to shirtgeklebt.net:80."
        self.assertIn("Nikto", _scan_intelligence(output)["failed"])


    def test_unknown_plugin_version_becomes_recommendation(self):
        raw = RAW + "\nPoweredBy[FlyingPress]\n"
        record = finding("FlyingPress possible missing authorization", "low",
                         "PoweredBy[FlyingPress]")
        record["description"] = "FlyingPress detected; exact version not disclosed."
        flag = [{"vuln_name": record["vuln_name"], "verdict": "corrected",
                 "corrected": "Possible FlyingPress issue; version unknown. Verify first.",
                 "issue": "Version unknown", "evidence": "PoweredBy[FlyingPress]"}]
        active, advice, rejected = apply_review([record], [], raw, flag)
        self.assertEqual(active, [])
        self.assertEqual(rejected, [])
        self.assertEqual(len(advice), 1)
        self.assertEqual(advice[0]["confidence"], "recommendation")
        self.assertIn("version unknown", advice[0]["description"])
        self.assertEqual(advice[0]["_review_original_description"], record["description"])

    def test_review_correction_preserves_original(self):
        record = finding("Confirmed weak setting from fixture", "low", SPF)
        flags = [{"vuln_name": record["vuln_name"], "verdict": "corrected",
                  "corrected": "Verified conservative wording.", "issue": "overstated",
                  "evidence": SPF}]
        active, advice, _ = apply_review([record], [], RAW, flags)
        self.assertEqual(len(active), 1)
        self.assertEqual(active[0]["description"], "Verified conservative wording.")
        self.assertEqual(active[0]["_review_original_description"], "Claim to assess")

    def test_reviewer_receives_all_scanner_sections_beyond_long_nmap(self):
        huge = RAW.replace(NMAP, NMAP + "\n" + "verbose nmap logs\n" * 800)
        balanced = review_evidence(huge, per_source=3500)
        self.assertIn(SPF, balanced)
        self.assertIn("Strict-Transport-Security", balanced)
        self.assertIn("Registrar: fixture", balanced)
        self.assertIn("8080/tcp open", balanced)
        self.assertLess(len(balanced), 18000)

    def test_reviews_final_names_and_drops_hallucinations(self):
        records = [
            finding("SPF softfail allows spoofing risk", "low", SPF),
            finding("Alternate HTTP/HTTPS ports 8080 and 8443 open", "low", "8080/tcp open http Cloudflare http proxy"),
            finding("Certificate SAN exposes API subdomain naming", "info", CERT),
            finding("Confirmed weak setting from fixture", "medium", "Strict-Transport-Security: max-age=2592000"),
        ]
        reviews = [{"vuln_name": "SPF softfail allows spoofing risk", "verdict": "hallucination",
                    "issue": "unsupported claim", "evidence": "", "corrected": "Check DMARC separately."},
                   {"vuln_name": "Alternate HTTP/HTTPS ports 8080 and 8443 open",
                    "verdict": "reclassified", "issue": "not a weakness", "evidence": "", "corrected": ""}]
        approved, advice, rejected = apply_review(records, [], RAW, reviews)
        self.assertEqual([x["vuln_name"] for x in approved], ["Confirmed weak setting from fixture"])
        self.assertEqual(len(advice), 2)
        self.assertEqual(len(rejected), 1)
        self.assertEqual(advice[0]["_review_flag"], "reclassified")
        self.assertEqual(advice[0]["confidence"], "recommendation")
        self.assertEqual(advice[1]["severity"], "info")
        self.assertIn("FINAL VULNERABILITIES:", reviewer_report(records, []))

    def test_rejected_findings_are_in_database_audit_but_not_active(self):
        import tempfile
        from pathlib import Path
        from penx_app.storage import db
        from penx_app.storage import db_backend
        with tempfile.TemporaryDirectory() as temp, \
             patch.object(db_backend, "DB_PATH", str(Path(temp) / "fixture.sqlite")):
            session = db.create_session("shirtgeklebt.net", status="pending")
            rejected = finding("Unverified SPF claim", "low", SPF)
            rejected.update(_review_flag="hallucination",
                            _review_issue="The reviewed evidence did not support spoofing")
            counts = db.save_assessment(session, {
                "vulnerabilities": [], "recommendations": [],
                "rejected_findings": [rejected], "exploits": [],
                "raw_scan": RAW, "full_response": "QA rejected spoofing claim",
                "risk_level": "LOW",
            })
            record = db.get_session(session)
            self.assertEqual(counts["rejected"], 1)
            self.assertEqual(counts["corrections"], 1)
            self.assertEqual(len(record["corrections"]), 1)
            self.assertEqual(db.active_vulnerabilities(record), [])
            self.assertEqual(record["fixes"], [])

    def test_unsupported_evidence_cannot_be_saved_as_vulnerability(self):
        unsupported = finding("Unverified report", "high", "nonexistent security scanner marker")
        approved, advice, rejected = apply_review([unsupported], [], RAW, [])
        self.assertEqual(approved, [])
        self.assertEqual(len(advice), 1)
        self.assertIn("Unverified scanner evidence", advice[0]["description"])
        self.assertEqual(rejected, [])

    def test_target_scope_and_adapter_options_are_explicit(self):
        self.assertIn("unsupported flag", run_tool_by_command(
            "curl -sk --max-time 30 -D - -o NUL https://shirtgeklebt.net/",
            authorized_target="shirtgeklebt.net"))
        # DNS service records are not valid host targets for shared scanners.
        # Reject before any tool call rather than treating this as a normal FQDN.
        self.assertIn("Invalid domain", run_tool_by_command(
            "dig _dmarc.shirtgeklebt.net TXT", authorized_target="shirtgeklebt.net"))
        self.assertIn("custom paths", run_tool_by_command(
            "curl https://shirtgeklebt.net/robots.txt", authorized_target="shirtgeklebt.net"))
        with patch("penx_app.scanners.tools.run_nmap", return_value="fixture result") as scan:
            self.assertEqual(run_tool_by_command("nmap -sV shirtgeklebt.net",
                             authorized_target="shirtgeklebt.net"), "fixture result")
            scan.assert_called_once_with("shirtgeklebt.net")

    def test_blocked_model_tools_terminate_loop_without_retries(self):
        with patch("penx_app.analysis.llm.CVE_DISCOVERY", False), patch("penx_app.analysis.llm.STRUCTURED_MODE", "off"), \
             patch("penx_app.analysis.llm.load_correction_rules", return_value=""), \
             patch("penx_app.analysis.llm.ask_llm", return_value="[TOOL: curl -sk https://shirtgeklebt.net/]") as ai, \
             patch("penx_app.analysis.llm.run_tool_by_command", return_value="[!] Blocked model tool call: unsupported flag") as tool, \
             patch("penx_app.analysis.llm.self_review", return_value={"review":"", "flags":[], "adjusted_risk":""}):
            data = llm.analyse_target("shirtgeklebt.net", RAW)
        ai.assert_called_once()
        tool.assert_called_once()
        self.assertEqual(data["vulnerabilities"], [])
        self.assertEqual(data["exploits"], [])

    def test_ai_exploit_suggestions_do_not_become_attempts(self):
        suggestion = {
            "exploit_name": "Imagined login brute force", "tool_used": "hydra",
            "payload": "not run", "result": "potential access", "notes": "untested"
        }
        draft = {"vulnerabilities": [], "recommendations": [], "exploits": [suggestion],
                 "risk_level": "LOW", "summary": "No verified exploit execution"}
        with patch("penx_app.analysis.llm.CVE_DISCOVERY", False), \
             patch("penx_app.analysis.llm.STRUCTURED_MODE", "auto"), \
             patch("penx_app.analysis.llm.load_correction_rules", return_value=""), \
             patch("penx_app.analysis.llm.ask_llm", return_value="RISK_LEVEL: LOW\nSUMMARY: No exploits run"), \
             patch("penx_app.analysis.llm.request_structured_report", return_value=draft), \
             patch("penx_app.analysis.llm.self_review", return_value={
                 "review": "", "adjusted_risk": "", "flags": []
             }), \
             patch("penx_app.analysis.llm.verify_findings", side_effect=lambda a, *_b, **_c: a):
            result = llm.analyse_target("shirtgeklebt.net", RAW)
        self.assertEqual(result["exploits"], [])
        self.assertIn("[UNEXECUTED MODEL EXPLOIT SUGGESTIONS", result["full_response"])
        self.assertIn("Imagined login brute force", result["full_response"])

    def test_whatweb_timeout_keeps_labeled_fallback_evidence(self):
        import tempfile
        from pathlib import Path
        from unittest.mock import Mock
        from penx_app.scanners import tools
        with tempfile.TemporaryDirectory() as path:
            script = Path(path) / "whatweb"
            script.write_text("fixture")
            reply = Mock()
            reply.status_code = 200
            reply.url = "https://shirtgeklebt.net"
            reply.headers = {"Server": "cloudflare"}
            reply.encoding = "utf-8"
            reply.raw.read.return_value = b"<html><title>Fixture</title></html>"
            with patch("penx_app.scanners.tools.WHATWEB_PATH", str(script)), \
                 patch("penx_app.scanners.tools.find_runtime", return_value="ruby"), \
                 patch("penx_app.scanners.tools.executable_env", return_value={}), \
                 patch("penx_app.scanners.tools.run_tool", return_value="[!] Timed out after 60s") as run, \
                 patch("penx_app.scanners.tools.requests.get", return_value=reply), \
                 patch("penx_app.scanners.tools._urls", return_value=["https://shirtgeklebt.net"]):
                result = tools.run_whatweb("shirtgeklebt.net")
        self.assertTrue(result.startswith("[Windows Python fingerprint fallback"))
        self.assertIn("Server=cloudflare", result)
        self.assertIn("Timed out after 60s", result)
        self.assertIn("-a", run.call_args.args[0])
        self.assertIn("1", run.call_args.args[0])

    def test_self_review_uses_balanced_scan_and_final_findings(self):
        report = {"vulnerabilities":[finding("SPF softfail allows spoofing risk", "low", SPF)],
                  "recommendations":[], "exploits":[], "risk_level":"LOW", "summary":"Fixture"}
        flags = ("REVIEW: SPF softfail allows spoofing risk | VERDICT: hallucination\n"
                 "EVIDENCE: none found in scan data\nISSUE: Insufficient evidence for actual spoofing\n"
                 "CORRECTED: Check DMARC separately\nADJUSTED_RISK_LEVEL: LOW")
        calls = []
        def fake_ask(messages, settings=None):
            calls.append(messages)
            return "RISK_LEVEL: LOW\nSUMMARY: First pass" if len(calls) == 1 else flags
        with patch("penx_app.analysis.llm.CVE_DISCOVERY", False), patch("penx_app.analysis.llm.STRUCTURED_MODE", "auto"), \
             patch("penx_app.analysis.llm.load_correction_rules", return_value=""), \
             patch("penx_app.analysis.llm.ask_llm", side_effect=fake_ask), \
             patch("penx_app.analysis.llm.request_structured_report", return_value=report), \
             patch("penx_app.analysis.llm.verify_findings", side_effect=lambda findings, *_a, **_kw: findings):
            result = llm.analyse_target("shirtgeklebt.net", RAW)
        self.assertEqual(result["vulnerabilities"], [])
        self.assertEqual(len(result["review"]["flags"]), 1)
        self.assertIn("[REJECTED FINDINGS]", result["full_response"])
        self.assertIn("FINAL VULNERABILITIES:", calls[1][1]["content"])
        self.assertIn(SPF, calls[1][1]["content"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
