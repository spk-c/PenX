"""Offline regression tests for assessment modes, trends and streaming."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

_TEMP = tempfile.TemporaryDirectory(prefix="penx_assessment_tests_")
os.environ["PENX_DB_ENGINE"] = "sqlite"
os.environ["PENX_DB_PATH"] = str(Path(_TEMP.name) / "assessment.db")

from penx_app.storage import db
import llm
from penx_app.analysis.llm_client import complete_chat
from penx_app.scanners.passive_recon import passive_recon
from penx_app.application.risk_assessment import (assessment_for_session, assess_finding, save_override)
from penx_app.application.scan_trends import compare_ids, history_trend, save_diff, export_diff_reports, report_text
from penx_app.scanners.tools import run_tool


class AssessmentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old = db.create_session("example.test")
        self.new = db.create_session("example.test")

    def tearDown(self):
        db.delete_full_session(self.new)
        db.delete_full_session(self.old)
        self.tmp.cleanup()

    def test_recommendations_do_not_receive_vulnerability_scores(self):
        row = (10, self.new, "Review WordPress plugins", "info",
               "recommendation", "", "", "Verify installed versions.")
        assessed = assess_finding(row)
        self.assertIsNone(assessed["score"])
        self.assertEqual(assessed["status"], "recommendation")
        with self.assertRaisesRegex(ValueError, "Recommendations"):
            assess_finding(row, {"score": 3})

    def test_possible_finding_has_explicit_status(self):
        row = (11, self.new, "Potential vulnerability", "low",
               "possible", "443", "https", "Verify actual software version.")
        assessed = assess_finding(row)
        self.assertEqual(assessed["status"], "potential finding")
        self.assertIsInstance(assessed["score"], int)

    def test_comparison_tracks_ports_and_findings_conservatively(self):
        db.save_vulnerability(self.old, "SMB misconfiguration", "low",
                              "445", "microsoft-ds", "legacy configuration")
        db.save_vulnerability(self.old, "Old finding", "medium", "80", "http", "historic")
        db.save_vulnerability(self.new, "SMB misconfiguration", "high",
                              "445", "microsoft-ds", "now more serious")
        db.save_vulnerability(self.new, "New issue", "low", "443", "https", "new")
        db.save_summary(self.old,
            "445/tcp open microsoft-ds Samba 4.1\n80/tcp open http Apache 2.4\nNmap done:",
            "analysis", "MEDIUM")
        db.save_summary(self.new,
            "445/tcp open microsoft-ds Samba 4.2\n443/tcp open https nginx 1.2\nNmap done:",
            "analysis", "HIGH")
        delta = compare_ids(self.old, self.new)
        self.assertTrue(delta["port_comparison_reliable"])
        self.assertIn("443/tcp", delta["new_ports"])
        self.assertIn("80/tcp", delta["missing_ports"])
        self.assertEqual(len(delta["service_changes"]), 1)
        self.assertEqual(len(delta["new_findings"]), 1)
        self.assertEqual(len(delta["not_observed_findings"]), 1)
        self.assertEqual(len(delta["severity_changes"]), 1)
        self.assertIn("not confirmed fixed", report_text(delta))
        self.assertEqual(len(history_trend("example.test")), 2)
        self.assertTrue(save_diff(delta, self.tmp.name).is_file())
        files = export_diff_reports(delta, self.tmp.name)
        self.assertEqual(set(files), {"json", "html", "pdf"})
        self.assertTrue(all(f.is_file() and f.stat().st_size > 50 for f in files.values()))

    def test_incomplete_scan_must_not_mark_ports_closed(self):
        db.save_summary(self.old, "Nmap done:\n80/tcp open http", "a", "LOW")
        db.save_summary(self.new, "[PASSIVE-ONLY RECON]\nNothing to probe", "b", "LOW")
        delta = compare_ids(self.old, self.new)
        self.assertFalse(delta["port_comparison_reliable"])
        self.assertEqual(delta["missing_ports"], {})

    def test_risk_score_and_explicit_manual_override(self):
        fid = db.save_vulnerability(
            self.new, "Password spraying", "high", "443", "auth",
            "Brute force detected", confidence="likely")
        row = db.get_vulnerabilities(self.new)[0]
        assessment = assess_finding(row)
        self.assertLess(assessment["score"], 80)
        self.assertIn("T1110", [x["id"] for x in assessment["techniques"]])
        self.assertNotIn("EPSS", assessment.keys())
        path = Path(self.tmp.name) / "manual.json"
        save_override(self.new, fid, score=33, techniques=["T1110"],
                      priority="quick win", path=path)
        reviewed = assessment_for_session(self.new, path=path)[0]
        self.assertEqual(reviewed["score"], 33)
        self.assertEqual(reviewed["score_source"], "manual override")
        with self.assertRaises(ValueError):
            save_override(self.old, fid, score=0, path=path)
        with self.assertRaises(ValueError):
            save_override(self.new, fid, score=101, path=path)

    def test_passive_looks_up_only_fixed_third_party_endpoints(self):
        urls = []
        def fake_query(url, **kwargs):
            urls.append(url)
            return [] if "crt.sh" in url else {"name": "example.test"}
        with patch("penx_app.scanners.passive_recon._query_json", side_effect=fake_query), \
             patch("penx_app.intelligence.shodan_enrichment.resolve_public_ipv4", return_value=([], "No public IP; skipped.")), \
             patch("penx_app.scanners.passive_recon._dns_lookup", return_value="A: no records"), \
             patch("penx_app.scanners.tools.run_whois", return_value="registry mocked"), \
             patch("penx_app.scanners.tools.run_nmap", side_effect=AssertionError("Active scan")), \
             patch("penx_app.scanners.tools.run_curl_headers", side_effect=AssertionError("Active HTTP")):
            result = passive_recon("example.test")
        self.assertIn("PASSIVE-ONLY", result)
        self.assertEqual(len(urls), 2)
        self.assertTrue(all(x.startswith(("https://crt.sh/", "https://rdap.org/"))
                            for x in urls))
        with self.assertRaises(ValueError):
            passive_recon("192.0.2.0/24")

    def test_passive_llm_never_dispatches_model_requested_scans(self):
        with patch("llm.discover", return_value={"candidates": []}), \
             patch("llm.format_report", return_value=""), \
             patch("llm.load_correction_rules", return_value=""), \
             patch("llm.ask_llm", return_value=
                   "[TOOL: nmap example.test]\nRISK_LEVEL: LOW\nSUMMARY: Passive only"), \
             patch("llm.self_review", return_value={
                   "review": "", "adjusted_risk": "", "flags": []}), \
             patch("llm.STRUCTURED_MODE", "off"), \
             patch("llm.VERIFY_SOURCES", False), \
             patch("llm.verify_findings", side_effect=lambda items, *_a, **_k: items), \
             patch("llm.run_tool_calls", side_effect=AssertionError("Tool run")):
            result = llm.analyse_target("example.test", "[RDAP] example", passive_only=True)
        self.assertEqual(result["risk_level"], "LOW")



class MainMenuWiringTests(unittest.TestCase):
    def test_assessment_menu_routes_and_live_toggle(self):
        import penx
        from penx_app.application.scan_outcome import ScanOutcome

        # No scans, network calls or model requests: check only CLI dispatch.
        choices = iter(["1", "", "9", "", "10", "", "11", "", "11", "", "8"])
        seen_modes = []
        with patch("builtins.input", side_effect=lambda *_: next(choices)), \
             patch("penx.banner", side_effect=lambda: seen_modes.append(
                 "1" if penx.live_output() else "0")), \
             patch("penx._execute_scan", return_value=ScanOutcome(True, True, "completed")) as scan, \
             patch("penx_app.cli.assessment_ui.compare_menu") as compare, \
             patch("penx_app.cli.assessment_ui.risk_menu") as risk, \
             patch("builtins.print") as output, \
             patch.dict(os.environ, {"PENX_LIVE_OUTPUT": "0"}):
            with self.assertRaises(SystemExit) as raised:
                penx.main_menu()
            self.assertEqual(raised.exception.code, 0)
            scan.assert_called_once_with()
            compare.assert_called_once_with()
            risk.assert_called_once_with()
            self.assertEqual(seen_modes[-2:], ["1", "0"])
            self.assertEqual(os.environ["PENX_LIVE_OUTPUT"], "0")
            self.assertFalse(any("Invalid choice" in str(call)
                                 for call in output.call_args_list))




class LlmAuthRecoveryTests(unittest.TestCase):
    def test_auth_errors_are_actionable_without_leaking_secrets(self):
        import requests
        from penx_app.analysis.llm_client import explain_http_error
        import llm

        for status in (401, 403):
            response = requests.Response()
            response.status_code = status
            error = requests.exceptions.HTTPError("secret-key-should-not-appear", response=response)
            message = explain_http_error(error)
            self.assertIn(f"HTTP {status}", message)
            self.assertIn("PENX_LLM_API_KEY", message)
            self.assertNotIn("secret-key-should-not-appear", message)
            with patch("llm.complete_chat", side_effect=error):
                self.assertIn(f"HTTP {status}", llm.ask_llm([{"role": "user", "content": "test"}]))

    def test_auth_preflight_prevents_running_scanners(self):
        import penx
        import requests

        response = requests.Response()
        response.status_code = 401
        error = requests.exceptions.HTTPError("Unauthorized", response=response)
        with patch("penx.prompt", return_value="example.test") as target_prompt, \
             patch("penx_app.analysis.llm_client.fetch_models", side_effect=error), \
             patch("penx.fetch_models", side_effect=error), \
             patch("penx.create_session") as create, \
             patch("penx.interactive_tool_run") as scan, \
             patch("penx.get_all_history") as history, \
             patch("penx.warn") as warn:
            penx.new_scan()
            create.assert_not_called()
            scan.assert_not_called()
            history.assert_not_called()
            self.assertTrue(any("401" in str(c) for c in warn.call_args_list))
            target_prompt.assert_called_once()
            self.assertEqual(target_prompt.call_args.kwargs, {"navigation": True})

    def test_auth_preflight_does_not_require_models_endpoint(self):
        import penx
        import requests
        response = requests.Response()
        response.status_code = 404
        with patch("penx.fetch_models", side_effect=requests.exceptions.HTTPError(
                "Not Found", response=response)):
            self.assertTrue(penx.llm_auth_preflight())

    def test_failed_analysis_preserves_raw_recon_but_removes_incomplete_session(self):
        import penx
        with tempfile.TemporaryDirectory() as temp:
            with patch("penx.APP_ROOT", Path(temp)), \
                 patch("penx.prompt", return_value="example.test"), \
                 patch("penx.llm_auth_preflight", return_value=True), \
                 patch("penx.get_all_history", return_value=[]), \
                 patch("penx.create_session", return_value=12), \
                 patch("penx.interactive_tool_run", return_value="80/tcp open http\nNmap done:"), \
                 patch("penx.analyse_target", side_effect=RuntimeError("unauthorized")), \
                 patch("penx.delete_full_session") as delete:
                penx.new_scan()
                delete.assert_called_once_with(12)
                output = Path(temp) / "reports" / "recon_SL12_unanalysed.txt"
                self.assertEqual(output.read_text(encoding="utf-8"), "80/tcp open http\nNmap done:")
                # Preserve retries safely under a new name; never overwrite
                # the first captured evidence after a failed session.
                second = penx.preserve_failed_recon(12, "another scan")
                self.assertNotEqual(second, output)
                self.assertEqual(output.read_text(encoding="utf-8"), "80/tcp open http\nNmap done:")
                self.assertEqual(second.read_text(encoding="utf-8"), "another scan")



class FakeSSE:
    headers = {"content-type": "text/event-stream"}
    def __enter__(self):
        return self
    def __exit__(self, *_):
        return False
    def raise_for_status(self):
        pass
    def iter_lines(self, **kwargs):
        chunks = [
            {"choices": [{"delta": {"content": "Hello "}}]},
            {"choices": [{"delta": {"content": "world"}}]},
        ]
        for item in chunks:
            yield "data: " + json.dumps(item)
            yield ""
        yield "data: [DONE]"
        yield ""


class LiveTests(unittest.TestCase):
    def test_sse_deltas_are_emitted_and_joined(self):
        chunks = []
        with patch("penx_app.analysis.llm_client.requests.post", return_value=FakeSSE()) as post:
            _, text = complete_chat(
                [{"role": "user", "content": "hello"}],
                url="http://localhost:8080/v1/chat/completions",
                models_url="http://localhost:8080/v1/models",
                model_name="offline-model", stream_callback=chunks.append)
        self.assertEqual(text, "Hello world")
        self.assertEqual(chunks, ["Hello ", "world"])
        self.assertTrue(post.call_args.kwargs["stream"])

    def test_streamed_subprocess_output(self):
        import subprocess

        started = []
        original_popen = subprocess.Popen

        def tracked_popen(*args, **kwargs):
            child = original_popen(*args, **kwargs)
            started.append(child)
            return child

        with patch.dict(os.environ, {"PENX_LIVE_OUTPUT": "1"}), \
             patch("penx_app.scanners.tools.subprocess.Popen", side_effect=tracked_popen):
            result = run_tool([sys.executable, "-c", "print('offline streaming works')"],
                              timeout=10)
        self.assertIn("offline streaming works", result)
        self.assertEqual(len(started), 1)
        self.assertIsNotNone(started[0].stdout)
        self.assertTrue(started[0].stdout.closed, "Live scanner stdout pipe leaked")


if __name__ == "__main__":
    unittest.main(verbosity=2)
