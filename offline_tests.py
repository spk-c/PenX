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
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
TEST_ROOT = ROOT / "tests"
SRC_ROOT = ROOT / "src"
# A hung suite must not block the whole run; real suites finish far sooner.
SUITE_TIMEOUT_SECONDS = 300


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


def _run_suite(suite: Path, env: dict) -> tuple[int, bytes, bytes, str | None]:
    """Run one suite in its own process. Returns (rc, out, err, error)."""
    try:
        # Never let offline suites inherit an interactive console. Otherwise
        # the native Windows Esc key reader can bypass patched input() calls
        # and block waiting for a real key (CI's non-TTY environment masks it).
        # Tests still receive deterministic mocked input() as usual; an
        # accidental unmocked read fails with EOF rather than hanging.
        result = subprocess.run([sys.executable, str(suite)], cwd=ROOT, env=env,
                                stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=SUITE_TIMEOUT_SECONDS, check=False)
        return result.returncode, result.stdout or b"", result.stderr or b"", None
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout or b""
        err = exc.stderr or b""
        if isinstance(out, str):
            out = out.encode("utf-8", "replace")
        if isinstance(err, str):
            err = err.encode("utf-8", "replace")
        return 124, out, err, f"timed out after {SUITE_TIMEOUT_SECONDS} s"
    except OSError as exc:
        return 1, b"", b"", f"Could not start {suite.name}: {exc}"


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
                inflight[pool.submit(_run_suite, suite, env)] = suite
            done, _ = concurrent.futures.wait(list(inflight),
                                             return_when=concurrent.futures.FIRST_COMPLETED)
            for future in done:
                suite = inflight.pop(future)
                _report_result(suite, *_result_of(future), failed=failed)
            if failed and fail_fast:
                # Fail-fast: drop everything not started; already-finished
                # suites still report, so one failure never hides another.
                for future, suite in list(inflight.items()):
                    if future.done():
                        _report_result(suite, *_result_of(future), failed=failed)
                    else:
                        future.cancel()
                inflight.clear()
                pending.clear()
    if failed:
        failed.sort(key=order.get)
        print('\n[FAIL] Failed suites: ' + ', '.join(failed), flush=True)
        return 1
    print(f"\n[OK] All {len(tests)} PenX offline test suites passed.", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
