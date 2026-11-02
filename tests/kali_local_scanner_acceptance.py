"""Practical Kali integration smoke against ONLY this process's loopback HTTP fixture.

Runs installed PenX CLI and real external scanner binaries. No external targets,
no model endpoints, and no generated shell commands from user input.
"""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import socketserver
import ssl
import subprocess
import tempfile
import threading

PORT = 8080
TLS_PORT = 8443
URL = f"http://127.0.0.1:{PORT}"
TLS_URL = f"https://127.0.0.1:{TLS_PORT}"
TARGET = "127.0.0.1"
AVAILABLE_PATHS = {"/", "/robots.txt", "/admin", "/docs"}


class LocalDNS(socketserver.BaseRequestHandler):
    """Minimal authoritative UDP fixture for penx-ci.test, never a forwarder."""
    def handle(self):
        request, conn = self.request
        if len(request) < 17:
            return
        index = 12
        labels = []
        while index < len(request):
            size = request[index]
            if size == 0:
                index += 1
                break
            if size > 63 or index + size >= len(request):
                return
            labels.append(request[index + 1:index + 1 + size].lower())
            index += size + 1
        if index + 4 > len(request):
            return
        question = request[12:index + 4]
        record_type = int.from_bytes(request[index:index + 2], "big")
        record_class = int.from_bytes(request[index + 2:index + 4], "big")
        has_a = labels == [b"penx-ci", b"test"] and record_type == 1 and record_class == 1
        header = (
            request[:2] + b"\\x81\\x80" + b"\\x00\\x01" +
            (b"\\x00\\x01" if has_a else b"\\x00\\x00") +
            b"\\x00\\x00\\x00\\x00"
        )
        answer = (
            b"\\xc0\\x0c\\x00\\x01\\x00\\x01\\x00\\x00\\x00\\x3c"
            b"\\x00\\x04\\x7f\\x00\\x00\\x01"
        ) if has_a else b""
        conn.sendto(header + question + answer, self.client_address)


class LocalFixture(BaseHTTPRequestHandler):
    def do_HEAD(self):
        self._send(body=False)

    def do_GET(self):
        self._send(body=True)

    def _send(self, *, body: bool):
        if self.path.split("?", 1)[0] not in AVAILABLE_PATHS:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        content = (
            "<html><head><title>PenX Kali localhost fixture</title>"
            '<meta name="generator" content="PenX-local-fixture"></head>'
            "<body><a href='/robots.txt'>robots</a>"
            "<a href='/docs'>docs</a><a href='/admin'>admin</a></body></html>"
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("X-Powered-By", "PenX-Local-Fixture")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        if body:
            self.wfile.write(content)

    def log_message(self, *args):
        pass


def run(*args: str, timeout: int = 90, env: dict | None = None):
    result = subprocess.run(args, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, timeout=timeout, env=env)
    excerpt = result.stdout[-3500:]
    print(f"[EXEC] {' '.join(args[:5])} | exit={result.returncode} | output={excerpt!r}", flush=True)
    return result


def assert_local_scan(scanner_id: str, key: str, target: str, directory: Path,
                      *, timeout: int = 90) -> None:
    output_dir = directory / scanner_id
    output_dir.mkdir()
    env = {**os.environ, "PENX_NMAP_TIMEOUT": "120", "PENX_NIKTO_TIMEOUT": "90"}
    result = run("penx", "scan", "--target", target, "--scanners", key,
                 "--authorized", "--consent", "--budget", "160",
                 "--format", "both", "--output", str(output_dir),
                 timeout=timeout, env=env)
    reports = list(output_dir.glob("*.json"))
    if len(reports) != 1:
        raise AssertionError(f"{scanner_id}: no unique JSON result (rc={result.returncode})")
    report = json.loads(reports[0].read_text(encoding="utf-8"))
    adapters = report.get("adapters", [])
    selected = [row for row in adapters if row["id"] == scanner_id]
    if len(selected) != 1:
        raise AssertionError(f"{scanner_id}: adapter missing from scan report: {adapters!r}")
    row = selected[0]
    print(f"[ADAPTER] {scanner_id}: {row['status']}, evidence={row['evidence']}",
          flush=True)
    if row["status"] != "COMPLETE" or not row["evidence"]:
        raise AssertionError(f"{scanner_id}: scanner did not finish with usable evidence: {row!r}")
    if result.returncode not in (0, 3):
        raise AssertionError(f"{scanner_id}: CLI exited with {result.returncode}")
    if len(list(output_dir.glob("*.sarif"))) != 1:
        raise AssertionError(f"{scanner_id}: SARIF report missing")


def main() -> None:
    # Deliberately only loopback: all active probes must stay inside the
    # self-owned HTTP fixture. No passive provider or external DNS enumeration.
    for name in ("nmap", "whatweb", "nikto", "penx", "nuclei",
                 "httpx-toolkit", "ffuf", "katana", "subfinder"):
        if not shutil.which(name):
            raise RuntimeError(f"Required Kali scanner not installed: {name}")
    server = ThreadingHTTPServer(("127.0.0.1", PORT), LocalFixture)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    tls_server = None
    tls_thread = None
    previous_ca = os.environ.get("SSL_CERT_FILE")
    try:
        with tempfile.TemporaryDirectory(prefix="penx-kali-local-") as temp:
            fixture_root = Path(temp)
            cert = fixture_root / "local-tls-cert.pem"
            key = fixture_root / "local-tls-key.pem"
            # Trust a self-generated certificate for this fixture only.
            # The private key never leaves the temporary container directory.
            subprocess.run([
                "openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048",
                "-keyout", str(key), "-out", str(cert), "-days", "1",
                "-subj", "/CN=127.0.0.1",
                "-addext", "subjectAltName=IP:127.0.0.1",
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=20)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certfile=str(cert), keyfile=str(key))
            tls_server = ThreadingHTTPServer(("127.0.0.1", TLS_PORT), LocalFixture)
            tls_server.socket = context.wrap_socket(tls_server.socket, server_side=True)
            tls_thread = threading.Thread(target=tls_server.serve_forever, daemon=True)
            tls_thread.start()
            os.environ["SSL_CERT_FILE"] = str(cert)
            templates = fixture_root / "vetted-templates"
            templates.mkdir()
            (templates / "penx-local-fixture.yaml").write_text(
                """id: penx-local-fixture
info:
  name: PenX controlled fixture verification
  author: penx-ci
  severity: low
http:
  - method: GET
    path:
      - "{{BaseURL}}/"
    matchers:
      - type: word
        part: header
        words:
          - "PenX-Local-Fixture"
""", encoding="utf-8")
            os.environ["PENX_NUCLEI_TEMPLATES"] = str(templates)
            result = run("penx", "preflight", "--target", TARGET,
                         "--scanners", "1,3,4,6,7,8,9,c,e", "--consent", timeout=45)
            if result.returncode:
                raise AssertionError("Kali preflight incorrectly marks installed scanners missing")
            failures = []
            # First run the distribution's executable directly. If the PenX
            # adapter fails, distinguish a broken Kali binary from adapter IO.
            native = run("whatweb", "-a", "1", URL, timeout=45)
            if native.returncode != 0:
                failures.append(f"native WhatWeb exit={native.returncode}")
            # Exercise real PenX adapters, gathering all results even if one
            # fails. This avoids hiding Nmap behind an earlier WhatWeb failure.
            for scanner_id, key, target, deadline in (
                ("http_headers", "4", URL, 45),
                ("whatweb", "3", URL, 75),
                ("nmap", "1", TARGET, 165),
                ("nikto", "6", URL, 125),
                ("nuclei", "7", URL, 120),
                ("httpx", "8", URL, 80),
                ("ffuf", "9", URL, 90),
                ("katana", "c", URL, 110),
                ("endpoint_mapping", "e", URL, 125),
                ("tls", "d", TLS_URL, 45),
            ):
                try:
                    assert_local_scan(scanner_id, key, target, Path(temp), timeout=deadline)
                except (AssertionError, subprocess.TimeoutExpired) as exc:
                    print(f"[FAIL] {scanner_id}: {exc}", flush=True)
                    failures.append(f"{scanner_id}: {exc}")
            # Also run the native Nikto command with a strict time cap to
            # distinguish a wrapper failure from the distribution executable.
            nikto = run("nikto", "-h", URL, "-nointeractive",
                        "-maxtime", "15s", timeout=55)
            if "Nikto" not in nikto.stdout and "nikto" not in nikto.stdout.lower():
                failures.append("Nikto did not emit its scanner banner")
            if failures:
                raise AssertionError("Kali localhost acceptance failures: " + "; ".join(failures))
            # Bind a real UDP DNS resolver to loopback only. Modify the
            # disposable container's resolver configuration for this scan,
            # restoring it even on failure. No query leaves this container.
            dns_server = socketserver.ThreadingUDPServer(("127.0.0.1", 53), LocalDNS)
            dns_thread = threading.Thread(target=dns_server.serve_forever, daemon=True)
            dns_thread.start()
            resolv_conf = Path("/etc/resolv.conf")
            original_resolv = resolv_conf.read_bytes()
            try:
                resolv_conf.write_text(
                    "nameserver 127.0.0.1\\noptions timeout:1 attempts:1\\n",
                    encoding="ascii",
                )
                assert_local_scan("dns", "5", "penx-ci.test",
                                  fixture_root, timeout=55)
            finally:
                resolv_conf.write_bytes(original_resolv)
                dns_server.shutdown()
                dns_server.server_close()
                dns_thread.join(timeout=10)

            # Subfinder is passive and needs online sources to produce real
            # discoveries. Prove its installed binary is found, and verify
            # a literal IP is rejected rather than sent to outside providers.
            preflight = run("penx", "preflight", "--target", TARGET,
                            "--scanners", "s", timeout=30)
            if preflight.returncode:
                failures.append("Subfinder missing from Kali preflight")
            no_external = run("penx", "scan", "--target", TARGET, "--scanners",
                              "s", "--authorized", "--format", "json",
                              "--output", str(fixture_root / "subfinder"), timeout=35)
            if no_external.returncode != 4:
                failures.append("Subfinder must reject an IP without passive provider calls")
            if failures:
                raise AssertionError("Kali localhost acceptance failures: " + "; ".join(failures))
            print("[PASS] Kali localhost: Nmap, WhatWeb, Nikto, HTTP headers,"
                  " Nuclei, httpx, ffuf, Katana, endpoint mapping,"
                  " verified TLS and DNS;", flush=True)
            print("[LIMITATION] WHOIS/Subfinder live provider queries are not"
                  " verified using loopback-only fixtures.", flush=True)
    finally:
        if previous_ca is None:
            os.environ.pop("SSL_CERT_FILE", None)
        else:
            os.environ["SSL_CERT_FILE"] = previous_ca
        if tls_server is not None:
            tls_server.shutdown()
            tls_server.server_close()
        if tls_thread is not None:
            tls_thread.join(timeout=10)
        server.shutdown()
        server.server_close()
        thread.join(timeout=10)


if __name__ == "__main__":
    main()
