"""Pure offline contracts for propagation of cancellation into scanner adapters."""
from __future__ import annotations

import threading
import unittest
from unittest.mock import Mock, patch

from penx_app.application.scanner_execution import run_selected_structured
from penx_app.domain.scan_models import ScanRequest, ScannerOutput
from penx_app.scanners import tools


def cancelled():
    return ScannerOutput("[!] Scanner cancelled by caller",
                         status="PARTIAL", evidence=False)


class NativeAdapterCancellationContracts(unittest.TestCase):
    def test_dispatcher_passes_token_only_to_explicitly_declared_adapter_port(self):
        token = threading.Event()
        seen = []
        def cancellable(target, *, cancel_event=None):
            seen.append(("cancellable", target, cancel_event))
            return ScannerOutput("fixture completed", evidence=True)
        def legacy(target):
            seen.append(("legacy", target))
            return ScannerOutput("legacy completed", evidence=True)
        result = run_selected_structured(
            ScanRequest("fixture.invalid", ("1", "2")),
            menu={"1": ("Nmap", cancellable), "2": ("WHOIS", legacy)},
            cancel_event=token,
        )
        self.assertEqual(seen, [
            ("cancellable", "fixture.invalid", token),
            ("legacy", "fixture.invalid"),
        ])
        self.assertTrue(all(row.status == "COMPLETE" for row in result.results))

    def test_adapter_typeerror_is_never_retried_as_a_second_scan(self):
        token = threading.Event()
        hits = []
        def failing(target, *, cancel_event=None):
            hits.append(target)
            raise TypeError("synthetic scanner adapter failure")
        result = run_selected_structured(
            ScanRequest("fixture.invalid", ("1",)),
            menu={"1": ("Nmap", failing)}, cancel_event=token,
        )
        self.assertEqual(hits, ["fixture.invalid"])
        self.assertEqual(result.results[0].status, "FAILED")
        self.assertFalse(result.has_evidence)

    def test_runner_wrapper_passes_actual_token_without_changing_legacy_calls(self):
        token = threading.Event()
        with patch.object(tools, "run_tool", return_value=cancelled()) as client:
            tools._run_external(["fake.exe"], timeout=10, cancel_event=token)
            self.assertIs(client.call_args.kwargs["cancel_event"], token)
            client.reset_mock()
            tools._run_external(["fake.exe"], timeout=10)
            self.assertNotIn("cancel_event", client.call_args.kwargs)

    def test_native_web_scanners_pass_cancel_to_runner(self):
        for name in ("nuclei", "httpx", "ffuf"):
            with self.subTest(scanner=name):
                token = threading.Event()
                executor = Mock(return_value=cancelled())
                with patch.object(tools, "web_endpoint", return_value="https://fixture.invalid"), \
                     patch.object(tools, "find_native", return_value="native.exe"), \
                     patch.object(tools, "nuclei_templates", return_value="templates"), \
                     patch.object(tools, "_run_external", executor):
                    result = getattr(tools, "run_" + name)(
                        "fixture.invalid", cancel_event=token)
                self.assertEqual(result.status, "PARTIAL")
                self.assertFalse(result.evidence)
                executor.assert_called_once()
                self.assertIs(executor.call_args.kwargs["cancel_event"], token)

    def test_subfinder_and_katana_are_cancellable_without_new_targets(self):
        for name in ("subfinder", "katana"):
            with self.subTest(scanner=name):
                token = threading.Event()
                executor = Mock(return_value=cancelled())
                with patch.object(tools, "web_endpoint", return_value="https://fixture.invalid"), \
                     patch.object(tools, "find_native", return_value="native.exe"), \
                     patch.object(tools, "_run_external", executor):
                    result = getattr(tools, "run_" + name)(
                        "fixture.invalid", cancel_event=token)
                self.assertEqual(result.status, "PARTIAL")
                self.assertFalse(result.evidence)
                executor.assert_called_once()
                self.assertIs(executor.call_args.kwargs["cancel_event"], token)

    def test_nmap_and_nikto_pass_cancel_into_process_runner(self):
        for name in ("nmap", "nikto"):
            with self.subTest(scanner=name):
                token = threading.Event()
                executor = Mock(return_value=cancelled())
                with patch.object(tools, "_host", return_value="fixture.invalid"), \
                     patch.object(tools, "_web_target", return_value="fixture.invalid"), \
                     patch.object(tools, "_executable", return_value="native.exe"), \
                     patch.object(tools, "NIKTO_PATH", ""), \
                     patch.object(tools, "_run_external", executor):
                    result = getattr(tools, "run_" + name)(
                        "fixture.invalid", cancel_event=token)
                self.assertEqual(result.status, "PARTIAL")
                self.assertFalse(result.evidence)
                executor.assert_called_once()
                self.assertIs(executor.call_args.kwargs["cancel_event"], token)

    def test_whatweb_cancel_never_falls_back_to_additional_http_requests(self):
        token = threading.Event()
        def executor(*_args, **_kwargs):
            token.set()
            return cancelled()
        with patch.object(tools, "_web_target", return_value="fixture.invalid"), \
             patch.object(tools, "WHATWEB_PATH", ""), \
             patch.object(tools, "_executable", return_value="whatweb"), \
             patch.object(tools, "_run_external", side_effect=executor) as process, \
             patch.object(tools.requests, "get",
                          side_effect=AssertionError("fallback must not run")):
            result = tools.run_whatweb("fixture.invalid", cancel_event=token)
        process.assert_called_once()
        self.assertEqual(result.status, "PARTIAL")
        self.assertFalse(result.evidence)

    def test_precancelled_native_wrappers_do_not_touch_external_io(self):
        names = ("nmap", "nikto", "whatweb", "nuclei", "httpx",
                 "ffuf", "subfinder", "katana")
        for name in names:
            with self.subTest(scanner=name):
                token = threading.Event()
                token.set()
                with patch.object(tools, "_run_external",
                                  side_effect=AssertionError("process started")), \
                     patch.object(tools, "find_native",
                                  side_effect=AssertionError("discovery started")):
                    result = getattr(tools, "run_" + name)(
                        "fixture.invalid", cancel_event=token)
                self.assertEqual(result.status, "PARTIAL")
                self.assertFalse(result.evidence)


if __name__ == "__main__":
    unittest.main(verbosity=2)
