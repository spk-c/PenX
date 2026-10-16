"""Target-scope and scanner option regressions for GitHub issue #42."""
from __future__ import annotations

import os
from pathlib import Path
import unittest
from unittest.mock import patch

from penx_app.scanners.tools import _host, run_nmap, run_tool_by_command, MAX_CIDR_ADDRESSES


class TargetValidationTests(unittest.TestCase):
    def test_invalid_cidr_never_falls_back_to_different_single_host(self):
        for target in (
            "192.168.1.1/33", "192.168.1.1/not-a-prefix",
            "2001:db8::1/129", "::1/nope", "999.1.1.1/24",
        ):
            with self.subTest(target=target), self.assertRaises(ValueError):
                _host(target)

    def test_oversized_networks_are_rejected(self):
        for target in ("0.0.0.0/0", "::/0", "192.168.0.0/16",
                       "2001:db8::/64", "10.0.0.0/8"):
            with self.subTest(target=target), self.assertRaisesRegex(ValueError, "CIDR target too large"):
                _host(target)

    def test_invalid_numeric_hostname_is_rejected(self):
        for target in ("999.1.1.1", "1.2.3", "123", "123.456",
                       "example.123"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                _host(target)

    def test_small_authorized_cidr_and_valid_ip_still_work(self):
        self.assertEqual(MAX_CIDR_ADDRESSES, 256)
        self.assertEqual(_host("192.0.2.128/25"), "192.0.2.128/25")
        self.assertEqual(_host("192.0.2.1/24"), "192.0.2.0/24")
        self.assertEqual(_host("2001:db8::/120"), "2001:db8::/120")
        self.assertEqual(_host("2001:db8::1"), "2001:db8::1")
        self.assertEqual(_host("example.test/path"), "example.test")
        self.assertEqual(_host("http://example.test/index"), "example.test")

    def test_unimplemented_nmap_pn_is_rejected_not_silently_ignored(self):
        with patch("penx_app.scanners.tools.run_nmap", return_value="scan-ok") as nmap:
            result = run_tool_by_command("nmap -Pn example.test", authorized_target="example.test")
            self.assertIn("unsupported flag", result)
            nmap.assert_not_called()
            self.assertEqual(
                run_tool_by_command("nmap -sV -sC example.test", authorized_target="example.test"),
                "scan-ok",
            )
            nmap.assert_called_once_with("example.test")

    def test_unsafe_cidr_never_starts_nmap_process(self):
        with patch("penx_app.scanners.tools._executable", side_effect=AssertionError("Should not launch Nmap")):
            result = run_nmap("0.0.0.0/0")
        self.assertIn("CIDR target too large", result)

    def test_nmap_timeout_is_configurable_and_bounded(self):
        with patch("penx_app.scanners.tools._executable", return_value="nmap"), \
             patch("penx_app.scanners.tools.run_tool", return_value="offline nmap fixture") as run, \
             patch.dict(os.environ, {"PENX_NMAP_TIMEOUT": "360"}):
            self.assertEqual(run_nmap("example.test"), "offline nmap fixture")
        self.assertEqual(run.call_args.kwargs["timeout"], 360)
        with patch("penx_app.scanners.tools._executable", return_value="nmap"), \
             patch("penx_app.scanners.tools.run_tool", return_value="fixture") as run, \
             patch.dict(os.environ, {"PENX_NMAP_TIMEOUT": "999999"}):
            run_nmap("example.test")
        self.assertEqual(run.call_args.kwargs["timeout"], 900)
        with patch("penx_app.scanners.tools._executable", return_value="nmap"), \
             patch("penx_app.scanners.tools.run_tool", return_value="fixture") as run, \
             patch.dict(os.environ, {"PENX_NMAP_TIMEOUT": "invalid"}):
            run_nmap("example.test")
        self.assertEqual(run.call_args.kwargs["timeout"], 180)

    def test_pytest_pythonpath_configuration_is_present(self):
        cfg = (Path(__file__).resolve().parents[1] / "pytest.ini").read_text(encoding="utf-8")
        self.assertIn("pythonpath = . src", cfg)
        self.assertIn("testpaths = tests", cfg)


if __name__ == "__main__":
    unittest.main(verbosity=2)
