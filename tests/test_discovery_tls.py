"""Offline regression coverage for opt-in discovery and TLS adapters."""
import unittest
from unittest.mock import Mock, patch

from penx_app.scanners.native_web_scanners import subfinder_args, katana_args
from penx_app.scanners.tools import run_subfinder, run_katana, run_tls_check, TOOLS_MENU, ScannerOutput


class DiscoveryTests(unittest.TestCase):
    def test_menu_registration(self):
        self.assertIn("s", TOOLS_MENU)
        self.assertNotIn("b", TOOLS_MENU)
        self.assertIn("c", TOOLS_MENU)
        self.assertIn("d", TOOLS_MENU)

    def test_subfinder_passive_fixed_flags(self):
        argv = subfinder_args("subfinder.exe", "example.test")
        self.assertEqual(argv[:3], ["subfinder.exe", "-d", "example.test"])
        self.assertNotIn("-active", argv)
        self.assertIn("-json", argv)

    def test_subfinder_filters_other_domains(self):
        raw = ('{"host":"a.example.test"}\n'
               '{"host":"example.test.evil.test"}\n'
               '{"host":"b.example.test"}')
        with patch("penx_app.scanners.tools.find_native", return_value="subfinder.exe"), patch(
            "penx_app.scanners.tools.run_tool", return_value=raw
        ):
            output = run_subfinder("example.test")
        self.assertIsInstance(output, ScannerOutput)
        self.assertIn("a.example.test", output)
        self.assertIn("b.example.test", output)
        self.assertNotIn("evil.test", output)

    def test_subfinder_rejects_ip(self):
        with patch("penx_app.scanners.tools.find_native") as find:
            output = run_subfinder("127.0.0.1")
        self.assertEqual(output.status, "FAILED")
        find.assert_not_called()

    def test_katana_same_origin_only(self):
        raw = (
            '{"request":{"endpoint":"https://example.test/a"}}\n'
            '{"request":{"endpoint":"https://bad.test/a"}}\n'
            '{"request":{"endpoint":"http://example.test/a"}}\n'
            '{"request":{"endpoint":"https://example.test:8443/a"}}')
        with patch("penx_app.scanners.tools.find_native", return_value="katana.exe"), patch(
            "penx_app.scanners.tools.run_tool", return_value=raw
        ):
            output = run_katana("https://example.test")
        self.assertIn("https://example.test/a", output)
        self.assertNotIn("bad.test", output)
        self.assertNotIn("http://example.test/a", output)
        self.assertNotIn(":8443", output)

    def test_katana_fixed_depth_and_scope(self):
        argv = katana_args("katana.exe", "https://example.test")
        self.assertEqual(argv[argv.index("-d") + 1], "1")
        self.assertEqual(argv[argv.index("-fs") + 1], "fqdn")

    def test_tls_requires_https(self):
        with patch("socket.create_connection") as connect:
            output = run_tls_check("http://example.test")
        self.assertEqual(output.status, "FAILED")
        connect.assert_not_called()

    def test_tls_enforces_tls12_minimum_before_handshake(self):
        import ssl
        cert = {"notAfter": "Dec 31 23:59:59 2099 GMT"}
        with patch("socket.create_connection") as connect, \
             patch("ssl.create_default_context") as factory:
            tls = factory.return_value.wrap_socket.return_value.__enter__.return_value
            tls.getpeercert.return_value = cert
            tls.version.return_value = "TLSv1.3"
            tls.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
            output = run_tls_check("https://example.test")
            self.assertEqual(factory.return_value.minimum_version, ssl.TLSVersion.TLSv1_2)
            self.assertEqual(output.status, "COMPLETE")
            self.assertTrue(output.evidence)
            self.assertIn("TLSv1.3", output)
            factory.return_value.wrap_socket.assert_called_once()
            # No TLS connection was established by the offline test.
            connect.assert_called_once_with(("example.test", 443), timeout=6)

    def test_tls_failed_handshake_does_not_claim_verified_tls(self):
        import ssl
        with patch("socket.create_connection"), \
             patch("ssl.create_default_context") as factory:
            factory.return_value.wrap_socket.side_effect = ssl.SSLError("unsupported protocol")
            output = run_tls_check("https://example.test")
        self.assertEqual(output.status, "FAILED")
        self.assertFalse(output.evidence)
        self.assertEqual(factory.return_value.minimum_version, ssl.TLSVersion.TLSv1_2)

    def test_tls_connection_failure_not_evidence(self):
        with patch("socket.create_connection", side_effect=OSError("unreachable")):
            output = run_tls_check("https://example.test")
        self.assertEqual(output.status, "FAILED")
        self.assertFalse(output.evidence)


if __name__ == "__main__":
    unittest.main()
