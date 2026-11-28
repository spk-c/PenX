"""Offline regression coverage for opt-in discovery and TLS adapters."""
import os
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
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

    def test_tls_unparseable_notafter_keeps_verified_handshake_evidence(self):
        import ssl
        cert = {"notAfter": "not-a-date"}
        with patch("socket.create_connection") as connect, \
             patch("ssl.create_default_context") as factory:
            tls = factory.return_value.wrap_socket.return_value.__enter__.return_value
            tls.getpeercert.return_value = cert
            tls.version.return_value = "TLSv1.3"
            tls.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
            output = run_tls_check("https://example.test")
        self.assertEqual(output.status, "PARTIAL")
        self.assertTrue(output.evidence)
        self.assertIn("[VERIFIED TLS HANDSHAKE]", output)
        self.assertIn("TLSv1.3", output)
        self.assertIn("Certificate notAfter value could not be parsed", output)
        self.assertEqual(
            output.diagnostics,
            "Certificate notAfter value could not be parsed; expiry unknown.")
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

    def test_tls_reports_certificate_identity_and_chain(self):
        cert = {
            "notAfter": "Dec 31 23:59:59 2099 GMT",
            "subject": ((('commonName', 'example.test'),),),
            "issuer": ((('commonName', 'Example Root CA'),),),
        }
        with patch("socket.create_connection") as connect, \
             patch("ssl.create_default_context") as factory:
            tls = factory.return_value.wrap_socket.return_value.__enter__.return_value
            tls.getpeercert.return_value = cert
            tls.version.return_value = "TLSv1.3"
            tls.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
            output = run_tls_check("https://example.test")
        self.assertEqual(output.status, "COMPLETE")
        self.assertIn("Certificate subject: commonName=example.test", output)
        self.assertIn("Certificate issuer: commonName=Example Root CA", output)
        self.assertIn("Certificate chain: verified against the system trust store", output)
        # The analysis layer only needs the stable prefix and days line.
        self.assertIn("[VERIFIED TLS HANDSHAKE] example.test:443", output)
        self.assertIn("Days remaining:", output)
        connect.assert_called_once_with(("example.test", 443), timeout=6)

    def test_tls_reports_unknown_identity_when_fields_absent(self):
        cert = {"notAfter": "Dec 31 23:59:59 2099 GMT"}
        with patch("socket.create_connection") as connect, \
             patch("ssl.create_default_context") as factory:
            tls = factory.return_value.wrap_socket.return_value.__enter__.return_value
            tls.getpeercert.return_value = cert
            tls.version.return_value = "TLSv1.3"
            tls.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
            output = run_tls_check("https://example.test")
        self.assertIn("Certificate subject: unknown", output)
        self.assertIn("Certificate issuer: unknown", output)
        connect.assert_called_once_with(("example.test", 443), timeout=6)

    def test_tls_hostname_mismatch_is_categorized(self):
        err = ssl.SSLCertVerificationError(
            1, "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: "
            "IP address mismatch, certificate is not valid for '127.0.0.1'.")
        with patch("socket.create_connection") as connect, \
             patch("ssl.create_default_context") as factory:
            factory.return_value.wrap_socket.side_effect = err
            output = run_tls_check("https://127.0.0.1:8443")
        self.assertEqual(output.status, "FAILED")
        self.assertFalse(output.evidence)
        self.assertIn("hostname mismatch", output)
        self.assertIn("127.0.0.1", output)
        connect.assert_called_once()

    def test_tls_self_signed_is_categorized(self):
        err = ssl.SSLCertVerificationError(
            1, "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: "
            "self-signed certificate")
        with patch("socket.create_connection") as connect, \
             patch("ssl.create_default_context") as factory:
            factory.return_value.wrap_socket.side_effect = err
            output = run_tls_check("https://example.test")
        self.assertEqual(output.status, "FAILED")
        self.assertFalse(output.evidence)
        self.assertIn("untrusted or self-signed", output)

    def test_tls_expired_certificate_is_categorized(self):
        err = ssl.SSLCertVerificationError(
            1, "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: "
            "certificate has expired")
        with patch("socket.create_connection") as connect, \
             patch("ssl.create_default_context") as factory:
            factory.return_value.wrap_socket.side_effect = err
            output = run_tls_check("https://example.test")
        self.assertEqual(output.status, "FAILED")
        self.assertFalse(output.evidence)
        self.assertIn("certificate expired", output)

    def test_tls_handshake_timeout_is_categorized(self):
        with patch("socket.create_connection", side_effect=TimeoutError("timed out")):
            output = run_tls_check("https://example.test")
        self.assertEqual(output.status, "FAILED")
        self.assertFalse(output.evidence)
        self.assertIn("handshake timeout", output)


class _LoopbackHandler(BaseHTTPRequestHandler):
    """Minimal handler; the TLS scanner only performs the handshake and closes."""
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass


class LiveLoopbackTLSTests(unittest.TestCase):
    """Ephemeral loopback TLS fixtures: real certs, real handshakes, loopback only.

    No external hosts and no model endpoints. Skipped when the platform cannot
    generate a self-signed certificate (e.g. openssl missing or broken); the
    mock tests above cover the diagnostic logic.
    """

    def _generate_cert(self, outdir, cn, san, days=30):
        os.makedirs(outdir, exist_ok=True)
        key = os.path.join(outdir, "key.pem")
        cert = os.path.join(outdir, "cert.pem")
        config = os.path.join(outdir, "openssl.cnf")
        with open(config, "w", encoding="utf-8") as fh:
            fh.write(
                "[ req ]\n"
                "default_bits = 2048\n"
                "prompt = no\n"
                "distinguished_name = req_distinguished_name\n"
                "x509_extensions = v3_req\n"
                "[ req_distinguished_name ]\n"
                "[ v3_req ]\n"
                "basicConstraints = CA:FALSE\n")
        env = dict(os.environ, OPENSSL_CONF=config)
        subprocess.run(
            ["openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048",
             "-keyout", key, "-out", cert, "-days", str(days),
             "-subj", f"/CN={cn}",
             "-addext", f"subjectAltName={san}",
             "-config", config],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=60, env=env)
        return cert, key

    def setUp(self):
        self.servers = []
        self.root = tempfile.mkdtemp(prefix="penx-tls-")
        try:
            self.cert_match, self.key_match = self._generate_cert(
                os.path.join(self.root, "match"), "127.0.0.1", "IP:127.0.0.1")
            self.cert_dns, self.key_dns = self._generate_cert(
                os.path.join(self.root, "dns"), "example.test", "DNS:example.test")
        except (OSError, subprocess.SubprocessError) as exc:
            self.addSkipTest(f"Unable to generate self-signed cert: {exc}")

    def tearDown(self):
        for srv in self.servers:
            try:
                srv.shutdown()
                srv.server_close()
            except Exception:
                pass
        shutil.rmtree(self.root, ignore_errors=True)

    def _serve(self, cert, key):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=cert, keyfile=key)
        srv = ThreadingHTTPServer(("127.0.0.1", 0), _LoopbackHandler)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.servers.append(srv)
        return port

    def test_trusted_match_reports_identity_and_chain(self):
        port = self._serve(self.cert_match, self.key_match)
        with patch.dict(os.environ, {"SSL_CERT_FILE": self.cert_match}):
            output = run_tls_check(f"https://127.0.0.1:{port}")
        self.assertEqual(output.status, "COMPLETE")
        self.assertIn("Certificate subject: commonName=127.0.0.1", output)
        self.assertIn("Certificate issuer: commonName=127.0.0.1", output)
        self.assertIn("Certificate chain: verified against the system trust store", output)
        self.assertIn("Days remaining:", output)

    def test_hostname_mismatch_is_categorized(self):
        # Cert presents only a DNS SAN; the target is an IP, so the name check
        # fails after the (trusted) certificate is accepted.
        port = self._serve(self.cert_dns, self.key_dns)
        with patch.dict(os.environ, {"SSL_CERT_FILE": self.cert_dns}):
            output = run_tls_check(f"https://127.0.0.1:{port}")
        self.assertEqual(output.status, "FAILED")
        self.assertFalse(output.evidence)
        self.assertIn("hostname mismatch", output)

    def test_untrusted_self_signed_is_categorized(self):
        # Without SSL_CERT_FILE the self-signed cert is not in the trust store.
        port = self._serve(self.cert_match, self.key_match)
        env = {k: v for k, v in os.environ.items() if k != "SSL_CERT_FILE"}
        with patch.dict(os.environ, env, clear=True):
            output = run_tls_check(f"https://127.0.0.1:{port}")
        self.assertEqual(output.status, "FAILED")
        self.assertFalse(output.evidence)
        self.assertIn("untrusted or self-signed", output)


if __name__ == "__main__":
    unittest.main()
