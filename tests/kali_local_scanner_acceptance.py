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
import subprocess
import tempfile
import threading
import time

PORT = 8080
URL = f"http://127.0.0.1:{PORT}"
TARGET = "127.0.0.1"


class LocalFixture(BaseHTTPRequestHandler):
    def do_HEAD(self):
        self._send(body=False)

    def do_GET(self):
        self._send(body=True)

    def _send(self, *, body: bool):
        content = (
            "<html><head><title>PenX Kali localhost fixture</title>"
            '<meta name="generator" content="PenX-local-fixture"></head>'
            "<body><a href='/robots.txt'>robots</a></body></html>"
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
    for name in ("nmap", "whatweb", "nikto", "penx"):
        if not shutil.which(name):
            raise RuntimeError(f"Required Kali scanner not installed: {name}")
    server = ThreadingHTTPServer(("127.0.0.1", PORT), LocalFixture)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix="penx-kali-local-") as temp:
            result = run("penx", "preflight", "--target", TARGET,
                         "--scanners", "1,3,4,6", "--consent", timeout=45)
            if result.returncode:
                raise AssertionError("Kali preflight incorrectly marks installed scanners missing")
            # Exercise *the real PenX adapters*, not mocked test doubles.
            assert_local_scan("http_headers", "4", URL, Path(temp), timeout=45)
            assert_local_scan("whatweb", "3", URL, Path(temp), timeout=75)
            assert_local_scan("nmap", "1", TARGET, Path(temp), timeout=165)
            # Native Nikto is separately capped: a full Nikto scan can run for
            # minutes even on localhost. Mark as executable smoke, not full
            # PenX-adapter acceptance.
            nikto = run("nikto", "-h", URL, "-nointeractive",
                        "-maxtime", "15s", timeout=55)
            if "Nikto" not in nikto.stdout and "nikto" not in nikto.stdout.lower():
                raise AssertionError("Nikto did not emit its own scanner banner")
            print("[PASS] Kali localhost: PenX HTTP headers, WhatWeb, Nmap;"
                  " real Nikto binary bounded smoke (not full adapter acceptance)", flush=True)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=10)


if __name__ == "__main__":
    main()
