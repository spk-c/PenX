"""PX-301 browser preview boundaries using a fake DOM/browser only.

No Playwright dependency, network connection, real page or scanner is used.
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import Mock, patch
import json
from pathlib import Path
import tempfile
import unittest

from penx_app.application.browser_preview import (
    BrowserScope, INIT_SCRIPT, _route_request, crawl_loopback,
)
from penx_app.application.browser_preview_cli import main


class FakeRoute:
    def __init__(self, url, method="GET"):
        self.request = SimpleNamespace(url=url, method=method)
        self.aborted = self.continued = False

    def abort(self):
        self.aborted = True

    def continue_(self):
        self.continued = True


class FakePage:
    def __init__(self, context):
        self.context = context
        self.url = "about:blank"
        self.seen = []

    def on(self, event, callback):
        self.context.popup_callback = callback

    def goto(self, url, **options):
        self.context.route_handler(FakeRoute(url))
        self.url = url
        self.seen.append(url)
        if self.context.inject_cross_origin:
            self.context.route_handler(FakeRoute("https://outside.invalid/secret"))
            self.context.route_handler(FakeRoute(url, "POST"))
        if url.endswith("/test"):
            return SimpleNamespace(status=500)
        return SimpleNamespace(status=200)

    def eval_on_selector_all(self, selector, expression, cap):
        if self.url.endswith("/next"):
            return []
        if selector == "a[href]":
            return ["/next", "/next", "https://outside.invalid/fail", "/?delete=1",
                    "javascript:alert(1)", "http://127.0.0.1:9999/port-hop",
                    "http://127.0.0.1:8088/test"]
        if selector == "form":
            return [{"method": "POST", "action": "/submit"},
                    {"method": "GET", "action": "https://outside.invalid/"}]
        raise AssertionError("Unexpected selector")


class FakeBrowserContext:
    def __init__(self):
        self.inject_cross_origin = True
        self.events = []
        self.page = FakePage(self)
        self.closed = False

    def add_init_script(self, *, script):
        self.init_script = script

    def route(self, pattern, callback):
        self.route_handler = callback
        self.events.append(pattern)

    def new_page(self):
        return self.page

    def close(self):
        self.closed = True


class FakeBrowser:
    def __init__(self):
        self.context = FakeBrowserContext()
        self.closed = False

    def new_context(self, **kwargs):
        self.options = kwargs
        return self.context

    def close(self):
        self.closed = True


class FakePlaywright:
    def __init__(self):
        self.browser = FakeBrowser()
        self.chromium = self

    def launch(self, **kwargs):
        self.launch_options = kwargs
        return self.browser

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return None


class PreviewTests(unittest.TestCase):
    def test_origin_policy_refuses_remote_private_encoded_and_url_credentials(self):
        bad = [
            "https://example.test", "http://192.168.1.5:8080",
            "http://10.0.0.1", "http://127.0.0.1.evil.test",
            "http://127.0.0.1@attacker.test", "http://user:pass@127.0.0.1",
            "ftp://127.0.0.1/resource", "file:///tmp/test",
            "http://127.0.0.1/?token=secret",
            "http://127.0.0.1/%2e%2e/admin", "http://127.0.0.1:0",
        ]
        for item in bad:
            with self.subTest(item=item), self.assertRaises(ValueError):
                BrowserScope.parse(item)
        scope = BrowserScope.parse("http://localhost:8088/app")
        self.assertTrue(scope.allows("http://127.0.0.1:8088/app/item"))
        self.assertFalse(scope.allows("http://127.0.0.1:8088/other"))
        self.assertFalse(scope.allows("http://127.0.0.1:9999/app/item"))
        self.assertFalse(scope.allows("https://127.0.0.1:8088/app/item"))
        self.assertFalse(scope.allows("http://[::1]:8088/app/item"))
        self.assertTrue(BrowserScope.parse("http://[::1]:8088/").allows(
            "http://[::1]:8088/path"))
        self.assertEqual(scope.candidate(scope.start_url, "/app/page?key=secret"), None)
        self.assertEqual(scope.candidate(scope.start_url, "javascript:alert(1)"), None)

    def test_method_and_origin_block_every_request(self):
        scope = BrowserScope.parse("http://127.0.0.1:8088/")
        stats = {"blocked_requests": 0}
        r1 = FakeRoute("http://127.0.0.1:8088/path", "GET")
        _route_request(r1, scope, stats)
        self.assertTrue(r1.continued)
        for url, method in [
            ("https://example.test/secret", "GET"),
            ("http://127.0.0.1:8088/modify", "POST"),
            ("http://127.0.0.1:9999/", "GET"),
            ("file:///etc/passwd", "GET"),
            ("http://127.0.0.1:8088/", "DELETE"),
        ]:
            route = FakeRoute(url, method)
            _route_request(route, scope, stats)
            self.assertTrue(route.aborted)
        self.assertEqual(stats["blocked_requests"], 5)

    def test_no_consent_prevents_browser_launch(self):
        factory = Mock()
        for opts in ({"authorized": False, "consent": True},
                     {"authorized": True, "consent": False}):
            with self.assertRaises(ValueError):
                crawl_loopback("http://127.0.0.1:8088/", playwright_factory=factory, **opts)
        factory.assert_not_called()

    def test_renders_only_bounded_same_origin_paths_with_no_active_vuln_claim(self):
        fake = FakePlaywright()
        report = crawl_loopback(
            "http://127.0.0.1:8088/", authorized=True, consent=True,
            max_pages=2, playwright_factory=lambda: fake, clock=lambda: 0)
        self.assertEqual(report["visited_pages"], 2)
        self.assertEqual(report["status"], "PARTIAL")
        self.assertGreaterEqual(report["blocked_requests"], 4)
        self.assertFalse(report["vulnerability_verified"])
        self.assertFalse(report["vulnerability_scanning_performed"])
        self.assertEqual(report["pages"][0]["path"], "/")
        self.assertIn("/next", report["pages"][0]["link_paths"])
        self.assertEqual(report["pages"][0]["forms"], [
            {"method": "POST", "action_path": "/submit"}])
        self.assertNotIn("outside.invalid", json.dumps(report))
        self.assertNotIn("delete=1", json.dumps(report))
        self.assertNotIn("alert(1)", json.dumps(report))
        self.assertEqual(fake.browser.context.options["service_workers"], "block")
        self.assertFalse(fake.browser.context.options["accept_downloads"])
        self.assertFalse(fake.browser.context.options["ignore_https_errors"])
        self.assertIn("WebSocket", fake.browser.context.init_script)
        self.assertEqual(fake.browser.launch_options["channel"], None)
        self.assertTrue(fake.browser.context.closed and fake.browser.closed)

    def test_bad_page_is_failed_not_a_clean_security_result(self):
        fake = FakePlaywright()
        fake.browser.context.inject_cross_origin = False
        report = crawl_loopback("http://127.0.0.1:8088/test",
                                authorized=True, consent=True,
                                playwright_factory=lambda: fake, clock=lambda: 0)
        self.assertEqual(report["status"], "PARTIAL")
        self.assertEqual(report["failed_pages"], 1)
        self.assertEqual(report["visited_pages"], 0)

    def test_crawler_limits_and_budget(self):
        factory = Mock()
        for vals in ({"max_pages": 0}, {"max_pages": 6}, {"timeout": 1},
                     {"budget": 1000}, {"max_pages": True}, {"channel": "remote"}):
            with self.subTest(vals=vals), self.assertRaises(ValueError):
                crawl_loopback("http://127.0.0.1/", authorized=True,
                               consent=True, playwright_factory=factory, **vals)
        factory.assert_not_called()

        fake = FakePlaywright()
        clocks = iter([0, 60])
        report = crawl_loopback("http://127.0.0.1:8088/",
                                authorized=True, consent=True,
                                playwright_factory=lambda: fake,
                                clock=lambda: next(clocks))
        self.assertEqual(report["status"], "PARTIAL")
        self.assertEqual(report["failed_pages"], 1)
        self.assertEqual(report["visited_pages"], 0)

    def test_cli_requires_explicit_flags_before_browser_or_file(self):
        with tempfile.TemporaryDirectory() as temp:
            self.assertEqual(main(["--url", "https://example.test",
                                   "--authorized", "--consent",
                                   "--output-dir", temp]), 2)
            self.assertEqual(main(["--url", "http://127.0.0.1:8088/",
                                   "--output-dir", temp]), 2)
            self.assertEqual(list(Path(temp).iterdir()), [])

    def test_cli_writes_one_new_report_without_overwrite(self):
        result = {
            "schema": "penx-browser-preview-v1", "status": "PARTIAL",
            "state": "collected-not-assessed", "pages": [],
            "vulnerability_verified": False,
        }
        with tempfile.TemporaryDirectory() as tmp:
            with patch("penx_app.application.browser_preview_cli.crawl_loopback",
                       return_value=result) as go:
                argv = ["--url", "http://127.0.0.1/", "--authorized", "--consent",
                        "--output-dir", tmp]
                self.assertEqual(main(argv), 1)
                self.assertEqual(main(argv), 1)
                self.assertEqual(go.call_count, 2)
            self.assertEqual(len(list(Path(tmp).glob("penx_browser_preview*.json"))), 2)
            self.assertFalse(json.loads(
                (Path(tmp) / "penx_browser_preview.json").read_text())["vulnerability_verified"])


if __name__ == "__main__":
    unittest.main()
