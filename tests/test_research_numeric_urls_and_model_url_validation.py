"""Offline tests for numeric-address research URL bypasses and LLM endpoint validation.

No network connections, local scanners, or real secrets are used.
"""
from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock

from penx_app.intelligence.search import _allowed_page_url, fetch_page
from penx_app.analysis.llm_client import normalize_base_url
from penx_app.settings import load_settings
from penx_app.setup.llm_setup import needs_setup


class NumericResearchUrlTests(unittest.TestCase):
    def test_legacy_numeric_loopback_and_private_ip_addresses_are_blocked(self):
        # libc/Winsock can interpret these as IPv4 even though
        # ipaddress.ip_address() rejects the abbreviated/encoded syntax.
        denied = (
            "127.1", "127.0.1", "2130706433", "0x7f000001",
            "0177.0.0.1", "0x7f.0.0.1",
            "192.168.1", "0300.0250.0.1",
        )
        for host in denied:
            with self.subTest(host=host):
                url = "https://" + host + "/status"
                self.assertFalse(_allowed_page_url(url))
                http = Mock(side_effect=AssertionError("must not connect"))
                self.assertIn("blocked", fetch_page(url, http_get=http))
                http.assert_not_called()

    def test_public_address_and_public_dns_names_remain_accepted(self):
        for url in ("https://8.8.8.8/", "https://0x08080808/",
                    "https://example.org/", "https://[2606:4700:4700::1111]/"):
            with self.subTest(url=url):
                self.assertTrue(_allowed_page_url(url))


class LocalModelUrlTests(unittest.TestCase):
    def test_invalid_model_endpoint_ports_and_credentials_are_rejected(self):
        invalid = (
            "http://user:secret@localhost:8080",
            "http://user@localhost:8080",
            "http://localhost:garbage",
            "http://localhost:65536",
            "http://localhost:0",
            "http://localhost:",
            "http://local host:8080",
            "http://localhost:8080/?query=1",
        )
        for url in invalid:
            with self.subTest(url=url):
                with self.assertRaises(ValueError):
                    normalize_base_url(url)
                with tempfile.TemporaryDirectory() as directory:
                    with self.assertRaises(ValueError):
                        load_settings(root=Path(directory), env={"PENX_LLM_URL": url})
                    env = Path(directory) / ".env"
                    env.write_text(
                        "PENX_LLM_URL=" + url + "\nPENX_MODEL=fixture-model\n",
                        encoding="utf-8",
                    )
                    # A malformed existing endpoint must request setup, not
                    # report a valid configured local model.
                    from unittest.mock import patch
                    with patch.dict("os.environ", {}, clear=True):
                        self.assertTrue(needs_setup(Path(directory)))

    def test_valid_local_endpoint_and_custom_path_remain_accepted(self):
        self.assertEqual(
            normalize_base_url("http://[::1]:8080/v1/chat/completions/"),
            "http://[::1]:8080",
        )
        self.assertEqual(
            normalize_base_url("https://local-model.example.org/api/v1"),
            "https://local-model.example.org/api",
        )


if __name__ == "__main__":
    unittest.main()
