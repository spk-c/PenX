"""Offline regression tests for scanner audit fixes (19 October 2026).

No external scan targets or network requests are used.
"""
from __future__ import annotations

from contextlib import redirect_stdout
from io import StringIO
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from penx_app.application.scanner_execution import run_selected
from penx_app.domain.scan_models import ScanRequest, ScannerOutput
from penx_app.scanners import tools
from penx_app.scanners.endpoint_inventory import EndpointInventory
from penx_app.scanners.native_web_scanners import ffuf_words
from penx_app.scanners.process_runner import run_tool, _terminal_safe_text


ORIGIN = "https://example.test"


class ScannerAuditFixTests(unittest.TestCase):
    def test_katana_strips_query_values_and_accepts_explicit_default_port(self):
        raw = "\n".join([
            json.dumps({"request": {"endpoint": ORIGIN + ":443/api/users?token=PRIVATE&id=123"}}),
            json.dumps({"request": {"endpoint": ORIGIN + "/home?session=SECRET"}}),
            json.dumps({"request": {"endpoint": "https://outside.test/private?secret=LEAK"}}),
        ])
        with patch.object(tools, "find_native", return_value="katana.exe"), \
             patch.object(tools, "_run_external", return_value=ScannerOutput(raw)):
            output = tools.run_katana(ORIGIN)
        self.assertEqual(output.status, "COMPLETE")
        self.assertTrue(output.evidence)
        self.assertIn(ORIGIN + "/api/users", output)
        self.assertIn(ORIGIN + "/home", output)
        for sensitive in ("PRIVATE", "SECRET", "LEAK", "outside.test", ":443/api"):
            self.assertNotIn(sensitive, output)

    def test_http_508_embedded_after_heading_stops_further_active_scanners(self):
        nikto = Mock()
        nuclei = Mock()
        result = run_selected(
            ScanRequest(ORIGIN, ("4", "6", "7"), active_consent=True),
            menu={
                "4": ("HTTP headers", lambda _: ScannerOutput(
                    "[https://example.test headers — Python requests]\n"
                    "HTTP 508 -> https://example.test\nRetry-After: 100"
                )),
                "6": ("nikto (optional)", nikto),
                "7": ("nuclei (explicit opt-in)", nuclei),
            },
        )
        nikto.assert_not_called()
        nuclei.assert_not_called()
        self.assertEqual(result["nikto (optional)"].status, "PARTIAL")
        self.assertEqual(result["nuclei (explicit opt-in)"].status, "PARTIAL")
        self.assertFalse(result["nikto (optional)"].evidence)

    def test_discovered_parent_directories_respect_state_change_filter(self):
        inv = EndpointInventory(ORIGIN)
        for path in (
            "/account/delete-user/one",
            "/member/logout.php/profile",
            "/checkout/payment",
            "/api/items",
        ):
            self.assertTrue(inv.add(ORIGIN + path, "katana"))
        self.assertEqual(inv.paths_for_fuzz(), [ORIGIN + "/api/"])
        self.assertEqual(inv.paths_for_probe(), ["api/items"])

    def test_custom_wordlist_rejects_state_changing_get_route(self):
        with tempfile.TemporaryDirectory() as folder:
            wordlist = Path(folder) / "paths.txt"
            for unsafe in ("logout", "delete-user", "reset_password", "checkout"):
                with self.subTest(unsafe=unsafe):
                    wordlist.write_text("health\n" + unsafe + "\n", encoding="utf-8")
                    with patch.dict(os.environ, {"PENX_FFUF_WORDLIST": str(wordlist)}):
                        with self.assertRaises(ValueError):
                            ffuf_words()
            wordlist.write_text("health\nrobots.txt\n", encoding="utf-8")
            with patch.dict(os.environ, {"PENX_FFUF_WORDLIST": str(wordlist)}):
                self.assertEqual(ffuf_words(), ["health", "robots.txt"])

    def test_nikto_ssl_error_is_never_promoted_to_evidence(self):
        for original_status in ("COMPLETE", "FAILED"):
            with self.subTest(original_status=original_status), \
                 patch.object(tools, "NIKTO_PATH", ""), \
                 patch.object(tools, "_executable", return_value="nikto.exe"), \
                 patch.object(tools, "_run_external", return_value=ScannerOutput(
                     "Nikto started\nssl connect failed",
                     status=original_status, evidence=original_status == "COMPLETE",
                 )):
                output = tools.run_nikto(ORIGIN)
            self.assertFalse(output.evidence)
            self.assertNotEqual(output.status, "COMPLETE")

    def test_live_output_escapes_controls_without_changing_scanner_evidence(self):
        code = r"import sys;sys.stdout.write('\x1b[2J\rINJECTED\n')"
        terminal = StringIO()
        with patch.dict(os.environ, {"PENX_LIVE_OUTPUT": "1"}), redirect_stdout(terminal):
            output = run_tool([sys.executable, "-c", code], timeout=10)
        self.assertEqual(output.status, "COMPLETE")
        self.assertIn("\x1b", output)
        self.assertNotIn("\x1b", terminal.getvalue())
        self.assertNotIn("\r", terminal.getvalue())
        self.assertIn(r"\x1b", terminal.getvalue())
        # Text-mode subprocess pipes perform universal-newline conversion.
        # Independently test raw carriage-return neutralization here.
        self.assertEqual(_terminal_safe_text("A\rB\x1b"), r"A\x0dB\x1b")
        self.assertIn("INJECTED", terminal.getvalue())

    def test_inventory_limit_is_reported_as_partial_in_mapping(self):
        old = EndpointInventory(ORIGIN)
        for index in range(150):
            self.assertTrue(old.add(ORIGIN + f"/old{index}", "katana"))
        current_url = ORIGIN + "/new"
        raw = json.dumps({"request": {"endpoint": current_url}})
        ffuf = json.dumps({"url": ORIGIN + "/found", "status": 200})

        def scanner_run(argv, **_kwargs):
            return ScannerOutput(raw if "-mdp" in argv else ffuf)

        with patch.object(tools, "find_native", return_value="scanner.exe"), \
             patch.object(tools, "_run_external", side_effect=scanner_run), \
             patch.object(tools, "load_inventory", return_value=old), \
             patch.object(tools, "save_inventory", return_value=Path("inventory.json")), \
             patch.object(tools.time, "sleep", return_value=None):
            output = tools.run_endpoint_mapping(ORIGIN)
        self.assertEqual(output.status, "PARTIAL")
        self.assertTrue(output.evidence)
        self.assertIn("could not be saved", output)
        self.assertEqual(len(old.entries), 150)
        self.assertNotIn(current_url, old.entries)


if __name__ == "__main__":
    unittest.main()
