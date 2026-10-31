"""Offline regression coverage for Issue #21: integrity and accuracy failures."""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

# offline_tests.py runs suites as separate processes; never touch real user DB.
_STORAGE = tempfile.TemporaryDirectory(prefix="penx_issue21_")
os.environ["PENX_DB_ENGINE"] = "sqlite"
os.environ["PENX_DB_PATH"] = str(Path(_STORAGE.name) / "tests.sqlite")

from penx_app.storage import db
import penx
from penx_app.analysis import llm
from penx_app.analysis.llm_client import IncompleteModelResponse, complete_chat
from penx_app.storage.db_training import export_training_data
from penx_app.reporting.export import _active_report_data
from penx_app.scanners.passive_recon import passive_recon
from penx_app.application.risk_assessment import assessment_for_session
from penx_app.application.scan_trends import compare_sessions
from penx_app.scanners.tools import recon_has_evidence


def assessment(*, vulnerabilities=None, recommendations=None):
    return {
        "vulnerabilities": vulnerabilities if vulnerabilities is not None else [],
        "recommendations": recommendations if recommendations is not None else [],
        "exploits": [], "raw_scan": "80/tcp open http\nNmap done:",
        "full_response": "RISK_LEVEL: MEDIUM\nSUMMARY: review pending",
        "risk_level": "MEDIUM",
    }


def vuln(name, severity="high", **extra):
    return {"vuln_name": name, "severity": severity, "port": "80",
            "service": "http", "description": "Test evidence", **extra}


class Issue21Tests(unittest.TestCase):
    def setUp(self):
        self.created = []

    def tearDown(self):
        for ident in self.created:
            db.delete_full_session(ident)

    def session(self, target="example.test"):
        sl = db.create_session(target)
        self.created.append(sl)
        return sl

    def test_error_only_recon_is_not_evidence(self):
        self.assertFalse(recon_has_evidence(""))
        self.assertFalse(recon_has_evidence("[!] Nmap is not installed"))
        self.assertFalse(recon_has_evidence("[EXIT CODE 1]\nFailed"))
        error_only = (
            "\n" + "=" * 50 + "\n[ NMAP OUTPUT ]\n" + "=" * 50 +
            "\n[!] Nmap is not installed\n" + "=" * 50 +
            "\n[ WHOIS OUTPUT ]\n" + "=" * 50 +
            "\n[!] WHOIS unavailable\n"
        )
        self.assertFalse(recon_has_evidence(error_only))
        self.assertTrue(recon_has_evidence(error_only +
                           "=" * 50 + "\n[ DNS OUTPUT ]\n" + "=" * 50 +
                           "\nA: 203.0.113.123\n"))
        self.assertFalse(recon_has_evidence(
            "[PASSIVE-ONLY RECON: example.test]\n\n"
            "[RDAP] Unavailable: HTTPError\n\n"
            "[CERTIFICATE TRANSPARENCY]\nNo entries returned.",
            passive_only=True))
        self.assertTrue(recon_has_evidence(
            "[PASSIVE-ONLY RECON: example.test]\n\n[RDAP]\n{\"name\": \"example.test\"}",
            passive_only=True))

    def test_error_only_scan_creates_no_session(self):
        with patch("penx.prompt", return_value="example.test"), \
             patch("penx.llm_auth_preflight", return_value=True), \
             patch("penx.get_all_history", return_value=[]), \
             patch("penx.interactive_tool_run", return_value="[!] Nmap is not installed"), \
             patch("penx.create_session") as create, \
             patch("penx.analyse_target") as analyse:
            self.assertIs(penx.new_scan(), False)
            create.assert_not_called()
            analyse.assert_not_called()

    def test_pending_session_invisible_until_atomic_commit(self):
        sl = db.create_session("pending.example", status="pending")
        self.created.append(sl)
        self.assertNotIn(sl, [row[0] for row in db.get_all_history()])
        from penx_app.reporting.export import fetch_all_history
        self.assertNotIn(sl, [row[0] for row in fetch_all_history()])
        self.assertEqual(db.get_session(sl)["history"][3], "pending")
        db.save_assessment(sl, assessment(vulnerabilities=[vuln("valid")]))
        self.assertIn(sl, [row[0] for row in db.get_all_history()])
        self.assertEqual(db.get_session(sl)["history"][3], "active")

    def test_atomic_assessment_rolls_back_on_bad_finding(self):
        sl = self.session()
        output = assessment(vulnerabilities=[
            vuln("valid", "high", fix="apply patch"),
            vuln("invalid", "unsupported-severity"),
        ])
        with self.assertRaises(ValueError):
            db.save_assessment(sl, output, model_name="test-model")
        record = db.get_session(sl)
        self.assertEqual(record["vulns"], [])
        self.assertEqual(record["fixes"], [])
        self.assertIsNone(record["summary"])

    def test_failed_save_removes_reserved_session(self):
        with patch("penx.prompt", return_value="example.test"), \
             patch("penx.llm_auth_preflight", return_value=True), \
             patch("penx.get_all_history", return_value=[]), \
             patch("penx.interactive_tool_run",
                   return_value="80/tcp open http\nNmap done:"), \
             patch("penx.analyse_target", return_value=assessment()), \
             patch("penx.create_session", return_value=912), \
             patch("penx.save_assessment", side_effect=ValueError("database write failed")), \
             patch("penx.preserve_failed_recon", return_value="local.txt"), \
             patch("penx.delete_full_session") as delete:
            self.assertIs(penx.new_scan(), False)
            delete.assert_called_once_with(912)

    def test_hallucinations_auditable_but_not_active(self):
        sl = self.session()
        rejected = vuln("Invented CVE", "critical", fix="unnecessary fix",
                        _review_flag="hallucination", _review_issue="Not supported")
        accepted = vuln("Real finding", "medium", fix="valid fix")
        stats = db.save_assessment(
            sl, assessment(vulnerabilities=[rejected, accepted],
                           recommendations=[{"vuln_name": "Best practice",
                                             "description": "Consider patching"}]))
        self.assertEqual(stats["corrections"], 1)
        record = db.get_session(sl)
        self.assertEqual(len(record["vulns"]), 3)
        self.assertEqual(len(record["corrections"]), 1)
        active = assessment_for_session(sl)
        self.assertEqual({x["name"] for x in active},
                         {"Real finding", "Best practice"})
        report = _active_report_data(record)
        self.assertEqual({x[2] for x in report["vulns"]},
                         {"Real finding", "Best practice"})
        self.assertEqual(len(report["fixes"]), 1)
        self.assertEqual(report["fixes"][0][3], "valid fix")
        from penx_app.application.scan_trends import _findings, history_trend
        self.assertNotIn(("invented cve", "80", "http"), _findings(record))
        self.assertEqual(history_trend("example.test")[-1]["findings"], 2)
        # A later human verification can re-enable a previously rejected item.
        rejected_id = next(row[0] for row in record["vulns"] if row[2] == "Invented CVE")
        db.save_correction(sl, rejected_id, "verified", "Old", "Verified", "Human audit")
        self.assertIn("Invented CVE", [x["name"] for x in assessment_for_session(sl)])

    def test_downgrade_is_not_exported_with_stale_severity(self):
        sl = self.session()
        a = db.save_vulnerability(sl, "Downgraded", "critical", "80", "http", "Old text")
        b = db.save_vulnerability(sl, "Corrected", "medium", "80", "http", "Old detail")
        db.save_summary(sl, "80/tcp open http", "analysis", "HIGH")
        db.save_correction(sl, a, "downgraded", "Critical", "New low impact",
                           "Classification disputed")
        db.save_correction(sl, b, "corrected", "Old detail", "Reviewed detail",
                           "Typo")
        with tempfile.TemporaryDirectory() as path:
            name = export_training_data(path)
            entries = [json.loads(s) for s in Path(name).read_text(encoding="utf-8").splitlines()]
        entry = next(x for x in entries if x["metadata"]["sl_no"] == sl)
        output = entry["messages"][1]["content"]
        self.assertNotIn("Downgraded", output)
        self.assertIn("Corrected", output)
        self.assertIn("Reviewed detail", output)
        self.assertEqual(entry["metadata"]["excluded_ambiguous_downgrades"], 1)

    def test_truncated_nonstream_text_rejected(self):
        response = Mock()
        response.json.return_value = {
            "choices": [{"finish_reason": "length",
                         "message": {"content": "RISK_LEVEL: HIGH\nSummary cut off..."}}],
            "usage": {"completion_tokens": 100},
        }
        response.raise_for_status = Mock()
        with patch("penx_app.analysis.llm_client.requests.post", return_value=response):
            with self.assertRaisesRegex(IncompleteModelResponse, "truncated"):
                complete_chat([{"role": "user", "content": "test"}],
                              url="http://127.0.0.1:8080/v1/chat/completions",
                              models_url="http://127.0.0.1:8080/v1/models",
                              model_name="explicit-model")

    def test_truncated_sse_text_rejected(self):
        response = MagicMock()
        response.__enter__.return_value = response
        response.headers = {"content-type": "text/event-stream"}
        response.iter_lines.return_value = iter([
            'data: {"choices":[{"delta":{"content":"RISK_LEVEL: HIGH"}}]}', "",
            'data: {"choices":[{"delta":{},"finish_reason":"length"}]}', "",
            "data: [DONE]", "",
        ])
        with patch("penx_app.analysis.llm_client.requests.post", return_value=response):
            with self.assertRaises(IncompleteModelResponse):
                complete_chat([{"role": "user", "content": "test"}],
                              url="http://127.0.0.1:8080/v1/chat/completions",
                              models_url="http://127.0.0.1:8080/v1/models",
                              model_name="explicit-model", stream_callback=lambda x: None)

    def test_last_tool_round_requires_final_synthesis(self):
        responses = [
            "[TOOL: nmap example.test]\nRISK_LEVEL: UNKNOWN",
            "RISK_LEVEL: LOW\nSUMMARY: Included latest tool evidence.",
        ]
        with patch("penx_app.analysis.llm.MAX_TOOL_LOOPS", 1), \
             patch("penx_app.analysis.llm.ask_llm", side_effect=responses) as ask, \
             patch("penx_app.analysis.llm.discover", return_value={"candidates": []}), \
             patch("penx_app.analysis.llm.format_report", return_value=""), \
             patch("penx_app.analysis.llm.load_correction_rules", return_value=""), \
             patch("penx_app.analysis.llm.self_review", return_value={"review": "",
                                                   "flags": [], "adjusted_risk": ""}), \
             patch("penx_app.analysis.llm.STRUCTURED_MODE", "off"), \
             patch("penx_app.analysis.llm.VERIFY_SOURCES", False), \
             patch("penx_app.analysis.llm.run_tool_calls", return_value="port 80 observed") as run, \
             patch("penx_app.analysis.llm.verify_findings", side_effect=lambda x, *_a, **_kw: x):
            result = llm.analyse_target("example.test", "raw data")
        self.assertEqual(ask.call_count, 2)
        run.assert_called_once()
        self.assertEqual(result["risk_level"], "LOW")
        self.assertIn("latest tool evidence", result["full_response"])

    def test_incomplete_nmap_xml_cannot_claim_closed_ports(self):
        def scan(session, xml):
            return {"history": (session, "example.test", "2026-10-14", "active"),
                    "summary": (session, session, xml, "analysis", "LOW"),
                    "vulns": []}
        old = ("<nmaprun><host><ports><port protocol='tcp' portid='80'>"
               "<state state='open'/></port></ports></host>"
               "<runstats><finished exit='success'/></runstats></nmaprun>")
        not_finished = ("<nmaprun><host><ports><port protocol='tcp' portid='443'>"
                        "<state state='open'/></port></ports></host></nmaprun>")
        delta = compare_sessions(scan(1, old), scan(2, not_finished))
        self.assertFalse(delta["port_comparison_reliable"])
        self.assertEqual(delta["missing_ports"], {})
        self.assertEqual(delta["service_changes"], [])
        error = not_finished.replace("</nmaprun>", "<runstats><finished exit='error'/>"
                                                      "</runstats></nmaprun>")
        self.assertFalse(compare_sessions(scan(1, old), scan(2, error))
                         ["port_comparison_reliable"])
        self.assertTrue(compare_sessions(scan(1, old), scan(2, old))
                        ["port_comparison_reliable"])
        self.assertFalse(compare_sessions(scan(1, old), scan(2, "[EXIT CODE 1]\n" + old))
                         ["port_comparison_reliable"])

    def test_malformed_certificate_entry_is_ignored(self):
        def provider(url, **kwargs):
            if "crt.sh" in url:
                return [None, "bad", {"name_value": "example.test"}]
            return {"name": "example.test"}
        with patch("penx_app.scanners.passive_recon._query_json", side_effect=provider), \
             patch("penx_app.scanners.passive_recon._dns_lookup", return_value="A: 8.8.8.8"), \
             patch("penx_app.scanners.tools.run_whois", return_value="WHOIS data"), \
             patch("penx_app.scanners.passive_recon.enrich_target", return_value=[]):
            raw = passive_recon("example.test")
        self.assertIn("example.test", raw)
        self.assertIn("[CERTIFICATE TRANSPARENCY]", raw)


if __name__ == "__main__":
    unittest.main(verbosity=2)
