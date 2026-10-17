"""Public-source research cannot connect to a privately resolved DNS address.

Mock DNS, socket creation and HTTP response handling: no actual network calls.
"""
from __future__ import annotations

import socket
import unittest
from unittest.mock import MagicMock, Mock, patch

from urllib3.exceptions import NewConnectionError

from penx_app.intelligence import search


def dns(ip: str, family=socket.AF_INET):
    address = (ip, 443) if family == socket.AF_INET else (ip, 443, 0, 0)
    return (family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", address)


class PublicOnlyHTTPSResearchTests(unittest.TestCase):
    def connection(self):
        return search._PublicOnlyHTTPSConnection("example.org", port=443, timeout=5)

    def test_all_private_dns_addresses_are_rejected_without_connect(self):
        for private in ("127.0.0.1", "10.2.3.4", "192.168.1.15",
                        "169.254.169.254", "172.16.1.1", "0.0.0.0"):
            with self.subTest(ip=private), \
                 patch.object(search.socket, "getaddrinfo", return_value=[dns(private)]), \
                 patch.object(search.socket, "socket") as create_socket:
                with self.assertRaises(NewConnectionError):
                    self.connection()._new_conn()
                create_socket.assert_not_called()

    def test_dns_is_resolved_once_and_only_public_sockaddr_is_connected(self):
        fake_sock = MagicMock()
        public_ip = "8.8.8.8"
        with patch.object(search.socket, "getaddrinfo",
                          return_value=[dns("127.0.0.1"), dns(public_ip)]) as lookup, \
             patch.object(search.socket, "socket", return_value=fake_sock) as make:
            result = self.connection()._new_conn()
        self.assertIs(result, fake_sock)
        lookup.assert_called_once_with("example.org", 443, type=socket.SOCK_STREAM)
        make.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM,
                                     socket.IPPROTO_TCP)
        fake_sock.connect.assert_called_once_with((public_ip, 443))
        self.assertEqual(fake_sock.settimeout.call_args.args, (5,))

    def test_ipv6_private_blocked_global_allowed(self):
        private = dns("::1", socket.AF_INET6)
        public = dns("2606:4700:4700::1111", socket.AF_INET6)
        fake_sock = MagicMock()
        with patch.object(search.socket, "getaddrinfo",
                          return_value=[private, public]), \
             patch.object(search.socket, "socket", return_value=fake_sock):
            self.connection()._new_conn()
        fake_sock.connect.assert_called_once_with(public[-1])

    def test_dns_failure_never_opens_socket(self):
        with patch.object(search.socket, "getaddrinfo",
                          side_effect=socket.gaierror("offline fixture")), \
             patch.object(search.socket, "socket") as make:
            with self.assertRaises(NewConnectionError):
                self.connection()._new_conn()
            make.assert_not_called()

    def test_public_socket_failure_closes_socket(self):
        fake_sock = MagicMock()
        fake_sock.connect.side_effect = OSError("synthetic failure")
        with patch.object(search.socket, "getaddrinfo",
                          return_value=[dns("8.8.8.8")]), \
             patch.object(search.socket, "socket", return_value=fake_sock):
            with self.assertRaises(NewConnectionError):
                self.connection()._new_conn()
        fake_sock.close.assert_called_once()

    def test_production_fetch_uses_dedicated_adapter_and_no_env_proxy(self):
        response = Mock()
        response.status_code = 200
        response.encoding = "utf-8"
        response.iter_content.return_value = [b"<p>SAFE PAGE</p>"]
        session = MagicMock()
        session.__enter__.return_value = session
        session.get.return_value = response
        with patch.object(search.requests, "Session", return_value=session) as make:
            result = search.fetch_page("https://example.org/safe")
        self.assertIn("SAFE PAGE", result)
        make.assert_called_once_with()
        self.assertFalse(session.trust_env)
        self.assertEqual(session.mount.call_args.args[0], "https://")
        self.assertIsInstance(session.mount.call_args.args[1],
                              search._PublicOnlyHTTPSAdapter)
        self.assertEqual(session.get.call_args.kwargs["allow_redirects"], False)
        response.close.assert_called_once()

    def test_unsafe_urls_rejected_before_creating_session(self):
        with patch.object(search.requests, "Session",
                          side_effect=AssertionError("must not create session")):
            for url in ("https://localhost/private", "https://127.1/",
                        "https://169.254.169.254/latest/",
                        "https://example.org/\nmalformed"):
                self.assertTrue(search.fetch_page(url).startswith("[!]"))

    def test_injected_offline_http_client_remains_supported(self):
        response = Mock()
        response.status_code = 200
        response.encoding = "utf-8"
        response.iter_content.return_value = [b"<p>Offline fixture</p>"]
        get = Mock(return_value=response)
        with patch.object(search.requests, "Session",
                          side_effect=AssertionError("must not create session")):
            result = search.fetch_page("https://example.org", http_get=get)
        self.assertIn("Offline fixture", result)
        get.assert_called_once()
        response.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
