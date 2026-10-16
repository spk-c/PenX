"""Offline coverage for native Windows adapter profiles (no real network/process)."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from penx_app.scanners.native_web_scanners import (find_native, ffuf_args, ffuf_words, web_endpoint,
                                 nuclei_args, httpx_args, summarize_output)
from penx_app.scanners.tools import (ScannerOutput, run_nuclei, run_httpx, run_ffuf,
                   run_tool_by_command, TOOLS_MENU)


class NativeWebScannerTests(unittest.TestCase):
    def test_profiles_registered_but_not_in_automatic_recon(self):
        self.assertIn("7", TOOLS_MENU)
        self.assertIn("8", TOOLS_MENU)
        self.assertIn("9", TOOLS_MENU)
        self.assertIn("not permitted",
                      run_tool_by_command("nuclei example.test", authorized_target="example.test"))

    def test_origin_rejects_path_query_credentials(self):
        from penx_app.scanners.tools import _web_target
        self.assertEqual(web_endpoint("https://example.test:8443", _web_target),
                         "https://example.test:8443")
        for target in ("https://example.test/other", "https://example.test/?x=1",
                       "https://name:pass@example.test"):
            with self.subTest(target=target):
                with self.assertRaises(ValueError):
                    web_endpoint(target, _web_target)

    def test_separate_bounded_nikto_and_nuclei_timeouts(self):
        from penx_app.scanners.tools import _scanner_timeout
        with patch.dict(os.environ, {
            "PENX_TIMEOUT": "900",
            "PENX_NIKTO_TIMEOUT": "180",
            "PENX_NUCLEI_TIMEOUT": "480",
        }):
            self.assertEqual(_scanner_timeout("nikto", 300), 180)
            self.assertEqual(_scanner_timeout("nuclei", 240), 480)
        with patch.dict(os.environ, {"PENX_NUCLEI_TIMEOUT": "50000"}):
            self.assertEqual(_scanner_timeout("nuclei", 240), 900)
        with patch.dict(os.environ, {"PENX_NIKTO_TIMEOUT": "abc"}):
            self.assertEqual(_scanner_timeout("nikto", 300), 300)

    def test_http_508_skips_expensive_selected_scanners_but_keeps_evidence(self):
        from penx_app.scanners import tools
        from unittest.mock import Mock
        nikto = Mock(return_value="should not run")
        nuclei = Mock(return_value="should not run")
        katana = Mock(return_value="should not run")
        menu = {
            "4": ("HTTP headers", lambda _: ScannerOutput(
                "HTTP 508 -> https://example.test/\nRetry-After: 14400")),
            "6": ("nikto (optional)", nikto),
            "7": ("nuclei (explicit opt-in)", nuclei),
            "c": ("katana (same-host crawl, explicit opt-in)", katana),
        }
        with patch.object(tools, "TOOLS_MENU", menu), \
             patch("penx_app.cli.cli_navigation.navigation_input", side_effect=["x", "y"]):
            output = tools.interactive_tool_run("https://example.test")
        for scanner in (nikto, nuclei, katana):
            scanner.assert_not_called()
        self.assertIn("HTTP 508", output)
        self.assertIn("PARTIAL", output)
        self.assertIn("Skipped active HTTP checks", output)

    def test_katana_jsonl_io_timeout_is_not_a_successful_crawl(self):
        from penx_app.scanners.tools import run_katana
        raw = ('{"request":{"endpoint":"https://example.test/"},"error":'
               '"GET https://example.test: cause=i/o timeout"}\n')
        with patch("penx_app.scanners.tools.find_native", return_value="katana.exe"), \
             patch("penx_app.scanners.tools.run_tool", return_value=raw):
            outcome = run_katana("https://example.test")
        self.assertEqual(outcome.status, "PARTIAL")
        self.assertFalse(outcome.evidence)
        self.assertIn("failed HTTP request", outcome)
        self.assertNotIn("[SAME-HOST CRAWL INVENTORY]", outcome)

    def test_nuclei_no_matches_does_not_claim_assurance(self):
        from penx_app.scanners.tools import run_nuclei
        with patch("penx_app.scanners.tools.find_native", return_value="nuclei.exe"), \
             patch("penx_app.scanners.tools.nuclei_templates", return_value=Path("fixtures/templates")), \
             patch("penx_app.scanners.tools.run_tool", return_value=ScannerOutput(
                 "[!] Tool returned no output.", status="FAILED", evidence=False)):
            outcome = run_nuclei("example.test")
        self.assertEqual(outcome.status, "COMPLETE")
        self.assertIn("not proof", outcome)

    def test_nuclei_bounded_non_oast(self):
        args = nuclei_args("nuclei.exe", "https://example.test")
        self.assertEqual(args[0], "nuclei.exe")
        self.assertIn("-ni", args)
        self.assertIn("-duc", args)
        self.assertIn("-or", args)
        self.assertEqual(args[args.index("-rl")+1], "2")
        self.assertEqual(args[args.index("-c")+1], "1")
        self.assertEqual(args[args.index("-pt")+1], "http,ssl")
        self.assertNotIn("-dast", args)

    def test_httpx_structured_output(self):
        with patch("penx_app.scanners.tools.find_native", return_value="httpx.exe"), patch(
                "penx_app.scanners.tools.run_tool", return_value='{"url":"https://example.test","status_code":200,"title":"Index","tech":["nginx"]}'
        ) as run:
            output = run_httpx("example.test")
        self.assertIsInstance(output, ScannerOutput)
        self.assertEqual(output.status, "COMPLETE")
        self.assertTrue(output.evidence)
        self.assertIn("technologies: nginx", output)
        args = run.call_args.args[0]
        self.assertIn("-j", args)
        self.assertIn("-duc", args)

    def test_nuclei_metadata_only_not_payload(self):
        raw = '{"template-id":"CVE-2026-12345","info":{"severity":"medium","name":"Test"},"matched-at":"https://example.test","response":"PRIVATE_PAYLOAD"}'
        with patch("penx_app.scanners.tools.find_native", return_value="nuclei.exe"), patch(
                "penx_app.scanners.tools.nuclei_templates", return_value=Path("fixtures/nuclei-templates")), patch(
                "penx_app.scanners.tools.run_tool", return_value=raw
        ):
            output = run_nuclei("example.test")
        self.assertIn("CVE-2026-12345", output)
        self.assertNotIn("PRIVATE_PAYLOAD", output)
        self.assertEqual(output.status, "COMPLETE")


    def test_nuclei_without_templates_stops_before_target_access(self):
        with patch("penx_app.scanners.tools.find_native", return_value="nuclei.exe"), \
             patch("penx_app.scanners.tools.nuclei_templates", return_value=None), \
             patch("penx_app.scanners.tools.run_tool") as run:
            outcome = run_nuclei("example.test")
        self.assertEqual(outcome.status, "FAILED")
        self.assertIn("--setup-native", outcome)
        run.assert_not_called()

    def test_python_httpx_collision_not_used(self):
        import types
        from penx_app.scanners import native_web_scanners as native
        with tempfile.TemporaryDirectory() as folder, \
             patch.object(native, "APP_ROOT", Path(folder)), \
             patch.object(native.shutil, "which", return_value="C:/Python/Scripts/httpx.exe"), \
             patch.object(native.subprocess, "run", return_value=types.SimpleNamespace(
                 stdout="", stderr="pip install 'httpx[cli]'", returncode=1)):
            self.assertIsNone(native.find_native("httpx"))

    def test_ffuf_time_limit_is_partial_not_empty_parse_failure(self):
        from penx_app.scanners.tools import _summarize_native_run
        result = _summarize_native_run("ffuf",
                 "[EXIT CODE 1]\\nMaximum running time for entire process reached, exiting.")
        self.assertEqual(result.status, "PARTIAL")
        self.assertFalse(result.evidence)

    def test_subfinder_empty_success_is_not_a_failure(self):
        from penx_app.scanners.tools import run_subfinder
        with patch("penx_app.scanners.tools.find_native", return_value="subfinder.exe"), \
             patch("penx_app.scanners.tools.run_tool", return_value=ScannerOutput(
                 "[!] Tool returned no output.", status="FAILED", evidence=False)):
            result = run_subfinder("example.test")
        self.assertEqual(result.status, "COMPLETE")
        self.assertFalse(result.evidence)

    def test_ffuf_bounded_wordlist_is_temp(self):
        captured = []
        def fake_run(args, timeout):
            self.assertEqual(args[args.index("-rate")+1], "2")
            self.assertEqual(args[args.index("-t")+1], "1")
            self.assertNotIn("-recursion", args)
            path = Path(args[args.index("-w")+1])
            self.assertTrue(path.exists())
            captured.append(path)
            self.assertLessEqual(len(path.read_text().splitlines()), 80)
            return '{"url":"https://example.test/robots.txt","status":200}'
        with patch("penx_app.scanners.tools.find_native", return_value="ffuf.exe"), patch(
                "penx_app.scanners.tools.run_tool", side_effect=fake_run
        ):
            output = run_ffuf("example.test")
        self.assertIn("robots.txt", output)
        self.assertEqual(output.status, "COMPLETE")
        self.assertFalse(captured[0].exists())

    def test_wordlist_rejects_scoping_escape(self):
        with tempfile.TemporaryDirectory() as folder:
            file = Path(folder) / "unsafe.txt"
            file.write_text("admin\n../other\n", encoding="utf-8")
            with patch.dict(os.environ, {"PENX_FFUF_WORDLIST": str(file)}):
                with self.assertRaises(ValueError):
                    ffuf_words()


    def test_header_collector_redacts_session_cookies(self):
        from unittest.mock import Mock
        from penx_app.scanners import tools
        response = Mock(status_code=200, url="https://example.test")
        response.headers = {
            "Server": "nginx",
            "Set-Cookie": "PHPSESSID=SENSITIVE_TOKEN; HttpOnly; Secure; SameSite=Lax",
        }
        with patch("penx_app.scanners.tools._urls", return_value=["https://example.test"]), \
             patch("penx_app.scanners.tools.requests.head", return_value=response):
            output = tools.run_curl_headers("example.test")
        self.assertIn("Set-Cookie: [REDACTED]", output)
        self.assertIn("HttpOnly", output)
        self.assertNotIn("SENSITIVE_TOKEN", output)
        self.assertEqual(output.status, "COMPLETE")

    def test_failed_scanner_does_not_discard_prior_results(self):
        from penx_app.scanners import tools
        from penx_app.cli.cli_navigation import navigation_input
        def fail(_):
            raise RuntimeError("adapter failure")
        tools_menu = {
            "1": ("first", lambda target: ScannerOutput("first result")),
            "2": ("second", fail),
        }
        with patch("penx_app.scanners.tools.TOOLS_MENU", tools_menu), \
             patch("penx_app.cli.cli_navigation.navigation_input", return_value="1 2"):
            result = tools.interactive_tool_run("example.test")
        self.assertIn("first result", result)
        self.assertIn("adapter failure", result)
        self.assertIn("PENX ADAPTER STATUS: FAILED", result)

    def test_missing_binary_never_scans(self):
        with patch("penx_app.scanners.tools.find_native", return_value=None), patch("penx_app.scanners.tools.run_tool") as run:
            output = run_nuclei("example.test")
        self.assertEqual(output.status, "FAILED")
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
