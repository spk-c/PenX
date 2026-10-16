#!/usr/bin/env python3
"""Run every standalone offline test suite with the current Python interpreter.

This is the single test entrypoint used by local Windows builds, GitHub CI,
and tagged Windows releases. Each suite runs in its own subprocess because
several tests manage temporary databases, process state and local HTTP mocks.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parent
TEST_ROOT = ROOT / "tests"
SRC_ROOT = ROOT / "src"


def discover_tests() -> list[Path]:
    """Discover all test_*.py suites in tests/, without a fixed list."""
    return sorted(path for path in TEST_ROOT.rglob("test_*.py") if path.is_file())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run all PenX offline regression suites")
    parser.add_argument("--list", action="store_true", help="Show discovered suite filenames without running them")
    parser.add_argument("--keep-going", action="store_true", help="Run remaining suites after a failure")
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
    print(f"[*] Running {len(tests)} PenX offline test suites...", flush=True)
    failed = []
    for index, suite in enumerate(tests, 1):
        print(f"\n[{index}/{len(tests)}] {suite.name}", flush=True)
        try:
            # Never let offline suites inherit an interactive console. Otherwise
            # the native Windows Esc key reader can bypass patched input() calls
            # and block waiting for a real key (CI's non-TTY environment masks it).
            # Tests still receive deterministic mocked input() as usual; an
            # accidental unmocked read fails with EOF rather than hanging.
            result = subprocess.run([sys.executable, str(suite)], cwd=ROOT, env=env,
                                    stdin=subprocess.DEVNULL, check=False)
        except OSError as exc:
            print(f"[FAIL] Could not start {suite.name}: {exc}", flush=True)
            return 1
        if result.returncode != 0:
            print(f"[FAIL] {suite.name} exited with status {result.returncode}.", flush=True)
            failed.append(suite.name)
            if not args.keep_going:
                return 1
    if failed:
        print('\n[FAIL] Failed suites: ' + ', '.join(failed), flush=True)
        return 1
    print(f"\n[OK] All {len(tests)} PenX offline test suites passed.", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
