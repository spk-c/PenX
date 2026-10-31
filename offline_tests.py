#!/usr/bin/env python3
"""Run every standalone offline test suite with the current Python interpreter.

This is the single test entrypoint used by local Windows builds, GitHub CI,
and tagged Windows releases. Each suite runs in its own subprocess because
several tests manage temporary databases, process state and local HTTP mocks.
Suites execute on a bounded worker pool (2 workers on CI, up to 4 locally);
fail-fast stays the default and ``--keep-going`` keeps its legacy behavior.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import os
import signal
import threading
import time
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
TEST_ROOT = ROOT / "tests"
SRC_ROOT = ROOT / "src"
# A hung suite must not block the whole run; real suites finish far sooner.
SUITE_TIMEOUT_SECONDS = 300
MAX_SUITE_OUTPUT_BYTES = 128 * 1024



def discover_tests() -> list[Path]:
    """Discover all test_*.py suites in tests/, without a fixed list."""
    return sorted(path for path in TEST_ROOT.rglob("test_*.py") if path.is_file())


def _default_workers() -> int:
    """Bounded parallelism: 2 on CI runners, up to 4 locally."""
    limit = 2 if os.environ.get("CI") else 4
    try:
        cores = os.cpu_count() or 2
    except OSError:
        cores = 2
    return max(1, min(limit, cores))


def _terminate_tree(proc: subprocess.Popen) -> None:
    """Kill the entire test process group on timeout or fail-fast."""
    if os.name == "nt":
        try:
            subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=5, check=False)
        except (OSError, subprocess.TimeoutExpired):
            pass
    else:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
    if proc.poll() is None:
        try:
            proc.kill()
        except ProcessLookupError:
            pass


class _BoundedOutput:
    """Keep the first and last bytes, preserving final failure tracebacks."""

    _MARKER = b"\n[... middle test output omitted ...]\n"

    def __init__(self, limit: int):
        self.limit = max(0, limit)
        self.data = bytearray()
        self.truncated = False
        self.marker = self._MARKER[:self.limit]
        self.head_size = (self.limit - len(self.marker)) // 2
        self.tail_size = self.limit - len(self.marker) - self.head_size

    def append(self, chunk: bytes) -> None:
        if not chunk or not self.limit:
            return
        if not self.truncated and len(self.data) + len(chunk) <= self.limit:
            self.data.extend(chunk)
            return
        if not self.truncated:
            combined = self.data + chunk
            self.truncated = True
        else:
            combined = self.data[self.head_size + len(self.marker):] + chunk
        tail = combined[-self.tail_size:] if self.tail_size else b""
        self.data = bytearray(combined[:self.head_size] if self.head_size and not self.truncated else
                              self.data[:self.head_size])
        if len(self.data) < self.head_size:
            self.data = bytearray(combined[:self.head_size])
        self.data.extend(self.marker)
        self.data.extend(tail)

    def output(self) -> bytes:
        return bytes(self.data)


def _run_suite(suite: Path, env: dict,
               cancel_event: threading.Event | None = None) -> tuple[int, bytes, bytes, str | None]:
    """Bounded first/tail logs; return only after pipe readers are joined."""
    proc = None
    buffers = [_BoundedOutput(MAX_SUITE_OUTPUT_BYTES),
               _BoundedOutput(MAX_SUITE_OUTPUT_BYTES)]
    workers: list[threading.Thread] = []
    code = 1
    error: str | None = None

    def drain(stream, buffer: _BoundedOutput) -> None:
        try:
            while True:
                chunk = stream.read(65536)
                if not chunk:
                    return
                buffer.append(chunk)
        except (OSError, ValueError):
            return

    try:
        options = ({"creationflags": getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)}
                   if os.name == "nt" else {"start_new_session": True})
        proc = subprocess.Popen(
            [sys.executable, str(suite)], cwd=ROOT, env=env,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            bufsize=0, **options,
        )
        for index, stream in enumerate((proc.stdout, proc.stderr)):
            worker = threading.Thread(target=drain, args=(stream, buffers[index]),
                                      daemon=True)
            worker.start()
            workers.append(worker)
        deadline = time.monotonic() + SUITE_TIMEOUT_SECONDS
        while True:
            if cancel_event is not None and cancel_event.is_set():
                code = 125
                error = "cancelled after another suite failed"
                _terminate_tree(proc)
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                code = 124
                error = f"timed out after {SUITE_TIMEOUT_SECONDS} s"
                _terminate_tree(proc)
                break
            try:
                proc.wait(timeout=min(0.1, remaining))
                code = proc.returncode
                break
            except subprocess.TimeoutExpired:
                continue
    except OSError as exc:
        code = 1
        error = f"Could not start {suite.name}: {exc}"
    finally:
        if proc is not None:
            if proc.poll() is None:
                _terminate_tree(proc)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                _terminate_tree(proc)
            # The child can exit before pipe-reader threads finish receiving
            # buffered output. Joining after wait fixes that race.
            for worker in workers:
                worker.join(timeout=3)
            if any(worker.is_alive() for worker in workers):
                _terminate_tree(proc)  # Also kills descendants holding inherited pipes.
                for worker in workers:
                    worker.join(timeout=1)
            if any(worker.is_alive() for worker in workers):
                code = 1
                error = "test output pipe did not close"
            for stream in (proc.stdout, proc.stderr):
                if stream is not None and not any(w.is_alive() for w in workers):
                    stream.close()
    return code, buffers[0].output(), buffers[1].output(), error


def _decode(data: bytes) -> str:
    return data.decode("utf-8", "replace")


def _report_result(suite: Path, returncode: int, out: bytes, err: bytes,
                   error: str | None, failed: list[str]) -> None:
    if error:
        print(f"\n[FAIL] {suite.name} {error}.", flush=True)
        failed.append(suite.name)
    elif returncode != 0:
        print(f"\n[FAIL] {suite.name} exited with status {returncode}.\n"
              + _decode(out) + _decode(err), flush=True)
        failed.append(suite.name)
    else:
        print(f"[PASS] {suite.name}", flush=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run all PenX offline regression suites")
    parser.add_argument("--list", action="store_true", help="Show discovered suite filenames without running them")
    parser.add_argument("--keep-going", action="store_true", help="Run remaining suites after a failure")
    parser.add_argument("--workers", type=int, default=0,
                        help="Number of parallel suite workers (default: auto)")
    args = parser.parse_args(argv)
    tests = discover_tests()
    if not tests:
        print("[FAIL] No test_*.py suites discovered.", flush=True)
        return 1
    if args.list:
        for test in tests:
            print(test.name)
        return 0
    # Each test runs as a script. Keep legacy top-level imports compatible
    # without installing a package or modifying the user's system PYTHONPATH.
    env = os.environ.copy()
    # Local .env preferences must not switch mocked subprocess tests to live
    # execution. Windows redirected output must support the terminal's Unicode.
    env['PYTHONUTF8'] = '1'
    env['PENX_LIVE_OUTPUT'] = '0'
    env["PYTHONPATH"] = os.pathsep.join(
        [str(ROOT), str(SRC_ROOT)] + ([env["PYTHONPATH"]] if env.get("PYTHONPATH") else [])
    )
    workers = args.workers if args.workers > 0 else _default_workers()
    workers = max(1, min(workers, len(tests)))
    print(f"[*] Running {len(tests)} PenX offline test suites...", flush=True)
    print(f"[*] Parallel workers: {workers} (per-suite timeout {SUITE_TIMEOUT_SECONDS} s)", flush=True)

    order = {suite.name: index for index, suite in enumerate(tests)}
    failed: list[str] = []
    pending = list(tests)
    inflight: dict[concurrent.futures.Future, Path] = {}
    fail_fast = not args.keep_going
    abort = threading.Event()

    def _result_of(future: concurrent.futures.Future) -> tuple[int, bytes, bytes, str | None]:
        try:
            return future.result()
        except Exception as exc:  # Defensive: worker contract changed.
            return 1, b"", b"", str(exc)

    with concurrent.futures.ThreadPoolExecutor(
            max_workers=workers, thread_name_prefix="penx-test") as pool:
        while pending or inflight:
            while pending and len(inflight) < workers:
                suite = pending.pop(0)
                inflight[pool.submit(_run_suite, suite, env, abort)] = suite
            done, _ = concurrent.futures.wait(list(inflight),
                                             return_when=concurrent.futures.FIRST_COMPLETED)
            for future in done:
                suite = inflight.pop(future)
                _report_result(suite, *_result_of(future), failed=failed)
            if failed and fail_fast:
                # Already running children receive a cooperative event and
                # terminate their whole process group; do not abandon futures.
                abort.set()
                pending.clear()
    if failed:
        failed.sort(key=order.get)
        print('\n[FAIL] Failed suites: ' + ', '.join(failed), flush=True)
        return 1
    print(f"\n[OK] All {len(tests)} PenX offline test suites passed.", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
