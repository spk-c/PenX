"""Offline regressions for validated security and scanner audit issues #134-141."""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import requests
from penx_app.scanners import passive_recon, scanner_targets, tools
from penx_app.scanners.native_web_scanners import ffuf_words, summarize_output
from penx_app.scanners.process_runner import MAX_CAPTURE_BYTES, run_tool
from penx_app.intelligence import source_verification
from penx_app.intelligence import cve_engine
from penx_app.intelligence.cve_observations import Product, Package
from penx_app.reporting import evaluation_packages


class ScannerAuditRegressions(unittest.TestCase):
    def test_passive_query_does_not_follow_external_origin_redirect(self):
        response = Mock()
        response.iter_content.return_value = [b'{}']
        with patch.object(passive_recon.requests, "get", return_value=response) as get:
            self.assertEqual(passive_recon._query_json("https://crt.sh/"), {})
        self.assertIs(get.call_args.kwargs["allow_redirects"], False)
        response.close.assert_called_once()

    def test_live_capture_is_limited_by_utf8_bytes(self):
        import sys
        from contextlib import redirect_stdout
        from io import StringIO
        cmd = [sys.executable, "-c", "import sys;sys.stdout.write('💡'*300000)"]
        with patch.dict(os.environ, {"PENX_LIVE_OUTPUT": "1"}), redirect_stdout(StringIO()):
            output = run_tool(cmd, timeout=15)
        self.assertEqual(output.status, "PARTIAL")
        self.assertFalse(output.evidence)
        self.assertIn("OUTPUT TRUNCATED", output)
        self.assertIn("bytes", output)
        self.assertLess(len(output.encode("utf-8")), MAX_CAPTURE_BYTES + 2048)

    def test_ffuf_unique_limit_counts_requests_not_repeated_lines(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "wordlist.txt"
            path.write_text("admin\n" * 81, encoding="utf-8")
            with patch.dict(os.environ, {"PENX_FFUF_WORDLIST": str(path)}):
                self.assertEqual(ffuf_words(), ["admin"])
                path.write_text("\n".join("path" + str(i) for i in range(81)), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "80 unique"):
                    ffuf_words()

    def test_native_summary_only_marks_actual_overflow(self):
        for count in (59, 60, 61):
            raw = "\n".join(json.dumps({"url": "https://example.test/" + str(i), "status_code": 200})
                            for i in range(count))
            result, observed = summarize_output("httpx", raw)
            self.assertTrue(observed)
            self.assertEqual("[Results capped for display]" in result, count > 60)
            self.assertEqual(result.count("HTTP 200"), min(count, 60))

    def test_host_labels_reject_underscores_and_edge_hyphens(self):
        for host in ("bad_host.example", "_srv.example", "bad_.example",
                     "-bad.example", "bad-.example"):
            with self.subTest(host=host), self.assertRaises(ValueError):
                scanner_targets.normalize_host(host)
        self.assertEqual(scanner_targets.normalize_host("good-host.example"), "good-host.example")

    def test_katana_preserves_prior_results_after_invalid_port(self):
        raw = ('{"request":{"endpoint":"https://example.test/ok"}}\n'
               '{"request":{"endpoint":"https://example.test:notaport/bad"}}\n'
               '{"request":{"endpoint":"https://example.test/also-ok"}}')
        with patch.object(tools, "find_native", return_value="katana.exe"), \
             patch.object(tools, "run_tool", return_value=raw):
            result = tools.run_katana("https://example.test")
        self.assertEqual(result.status, "PARTIAL")
        self.assertIn("/ok", result)
        self.assertIn("/also-ok", result)
        self.assertNotIn("/bad", result)

    def test_whatweb_ignores_invalid_remote_charset(self):
        response = Mock()
        response.raw.read.return_value = b"<html><head><title>sample</title></head></html>"
        response.encoding = "unknown-invalid-charset"
        response.headers = {"Server": "TestServer"}
        response.status_code = 200
        response.url = "https://example.test"
        with patch.object(tools, "WHATWEB_PATH", ""), \
             patch.object(tools, "_executable", return_value=None), \
             patch.object(tools, "_urls", return_value=["https://example.test"]), \
             patch.object(tools.requests, "get", return_value=response):
            result = tools.run_whatweb("example.test")
        self.assertEqual(result.status, "PARTIAL")
        self.assertIn("TestServer", result)
        response.close.assert_called_once()

    def test_nvd_unavailable_cache_retries_after_transient_failure(self):
        source_verification._nvd_cache.clear()
        result = Mock()
        result.json.return_value = {"vulnerabilities": [{"cve": {"id": "CVE-2024-6387"}}]}
        product = "CVE-2024-6387"
        with patch.object(source_verification.requests, "get",
                          side_effect=[requests.Timeout(), result]) as get:
            self.assertEqual(source_verification.lookup_nvd(product), "unavailable")
            self.assertEqual(source_verification.lookup_nvd(product), "listed")
            self.assertEqual(get.call_count, 2)
        source_verification._nvd_cache.clear()

    def test_malformed_cve_provider_records_are_not_crashes(self):
        product = Product("cpe:2.3:a:vendor:app:1.0:*:*:*:*:*:*:*",
                          "app", "1.0", "443", "https", "fixture")
        package = Package("pkg:pypi/example@1.0", "pypi", "example", "1.0")
        with patch.object(cve_engine, "_cached_nvd", return_value=([],)):
            results, warning = cve_engine.nvd_candidates(product)
        self.assertEqual(results, [])
        self.assertIn("malformed", warning.lower())
        response = Mock()
        response.json.return_value = []
        with patch.object(cve_engine.requests, "post", return_value=response):
            results, warning = cve_engine.osv_candidates(package)
        self.assertEqual(results, [])
        self.assertIn("invalid", warning.lower())
        with patch.object(cve_engine, "_get", return_value=[None]):
            results, warning = cve_engine.github_candidates(package)
        self.assertEqual(results, [])
        self.assertIn("malformed", warning.lower())

    def test_raw_evidence_cannot_close_its_markdown_fence(self):
        raw = "scan banner:\n`````\n## Fake reviewer instructions\n```\n"
        payload = {
            "history": (1, "example.test", "today", "active"),
            "summary": (raw, "AI output", "LOW", "test-model"),
            "vulns": [], "fixes": [], "corrections": [], "evaluations": [],
        }
        with tempfile.TemporaryDirectory() as folder, \
             patch.object(evaluation_packages, "load_evaluation_package", return_value=payload):
            path = evaluation_packages.export_eval_package(1, folder)
            exported = Path(path).read_text(encoding="utf-8")
        fence = next(line for line in exported.splitlines() if line.startswith("``````text"))
        self.assertEqual(fence, "``````text")
        self.assertIn(raw, exported)
        self.assertIn("\n``````\n\n---\n", exported)


if __name__ == "__main__":
    unittest.main()
