"""Offline contracts for Ctrl+C cancellation across terminal and adapter layers."""
from __future__ import annotations

from contextlib import redirect_stdout
from io import StringIO
import signal
import threading
import unittest
from unittest.mock import Mock, patch

from penx_app.cli import scanner_cancellation, scanner_menu
from penx_app.domain.scan_models import ScannerOutput


class SignalHandlerContracts(unittest.TestCase):
    def test_first_sigint_sets_token_second_raises_and_handler_is_restored(self):
        previous = object()
        installed = []

        def register(kind, handler):
            self.assertEqual(kind, signal.SIGINT)
            installed.append(handler)

        with patch.object(scanner_cancellation.signal, "getsignal",
                          return_value=previous), \
             patch.object(scanner_cancellation.signal, "signal",
                          side_effect=register):
            with scanner_cancellation.scanner_cancellation() as event:
                self.assertFalse(event.is_set())
                self.assertEqual(len(installed), 1)
                installed[0](signal.SIGINT, None)
                self.assertTrue(event.is_set())
                with self.assertRaises(KeyboardInterrupt):
                    installed[0](signal.SIGINT, None)
            self.assertIs(installed[1], previous)

    def test_exception_restores_previous_handler(self):
        previous = object()
        with patch.object(scanner_cancellation.signal, "getsignal",
                          return_value=previous), \
             patch.object(scanner_cancellation.signal, "signal") as install:
            with self.assertRaisesRegex(RuntimeError, "adapter failed"):
                with scanner_cancellation.scanner_cancellation():
                    raise RuntimeError("adapter failed")
            self.assertIs(install.call_args_list[-1].args[1], previous)

    def test_non_main_thread_does_not_install_process_handler(self):
        with patch.object(scanner_cancellation.threading, "current_thread",
                          return_value=object()), \
             patch.object(scanner_cancellation.signal, "signal") as install:
            with scanner_cancellation.scanner_cancellation() as event:
                self.assertIsInstance(event, threading.Event)
                event.set()
                self.assertTrue(event.is_set())
        install.assert_not_called()

    def test_restricted_signal_installation_retains_event_contract(self):
        with patch.object(scanner_cancellation.signal, "signal",
                          side_effect=ValueError("not allowed")):
            with scanner_cancellation.scanner_cancellation() as event:
                self.assertFalse(event.is_set())


class ScannerPickerCancellationTests(unittest.TestCase):
    def test_first_ctrl_c_stops_queue_and_skips_formatter(self):
        handlers = []
        previous = object()
        completed = []
        launched = []

        def register(_kind, handler):
            handlers.append(handler)

        def first(target, *, cancel_event=None):
            launched.append(("nmap", target))
            self.assertIsNotNone(cancel_event)
            handlers[0](signal.SIGINT, None)
            completed.append("earlier evidence")
            return ScannerOutput("80/tcp open", status="COMPLETE", evidence=True)

        def forbidden(_target):
            launched.append(("whois", _target))
            raise AssertionError("Next scanner must not start after Ctrl+C")

        menu = {"1": ("Nmap", first), "2": ("WHOIS", forbidden)}
        fmt = Mock(side_effect=AssertionError("Partial result formatted"))
        with patch("penx_app.cli.cli_navigation.navigation_input",
                   return_value="1 2"), \
             patch.object(scanner_cancellation.signal, "getsignal",
                          return_value=previous), \
             patch.object(scanner_cancellation.signal, "signal",
                          side_effect=register), \
             redirect_stdout(StringIO()) as output:
            result = scanner_menu.interactive_tool_run(
                "example.test", menu=menu, formatter=fmt,
            )
        self.assertIsNone(result)
        self.assertEqual(launched, [("nmap", "example.test")])
        self.assertEqual(completed, ["earlier evidence"])
        self.assertIn("cancelled", output.getvalue())
        self.assertIs(handlers[-1], previous)
        fmt.assert_not_called()

    def test_normal_result_preserves_historical_formatter_contract(self):
        observed = []

        def run(target, *, cancel_event=None):
            self.assertEqual(target, "example.test")
            self.assertIsNotNone(cancel_event)
            self.assertFalse(cancel_event.is_set())
            return ScannerOutput("open", status="COMPLETE", evidence=True)

        def formatter(result):
            observed.append(result)
            return "formatted"

        with patch("penx_app.cli.cli_navigation.navigation_input",
                   return_value="1"):
            result = scanner_menu.interactive_tool_run(
                "example.test", menu={"1": ("Nmap", run)},
                formatter=formatter,
            )
        self.assertEqual(result, "formatted")
        self.assertEqual(observed[0]["Nmap"].status, "COMPLETE")

    def test_declined_active_consent_installs_no_handler(self):
        with patch("penx_app.cli.cli_navigation.navigation_input",
                   side_effect=["7", "no"]), \
             patch.object(scanner_menu, "scanner_cancellation",
                          side_effect=AssertionError("Cancellation context reached")):
            result = scanner_menu.interactive_tool_run(
                "example.test",
                menu={"7": ("Nuclei", lambda _target: "bad")},
                formatter=lambda *_: "wrong",
            )
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
