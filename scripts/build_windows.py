#!/usr/bin/env python3
"""Single source of truth for PenX's folder-based Windows PyInstaller build.

Used by build-exe.bat, CI smoke tests and the release workflow. Never bundles
third-party scanner executables or local configuration, databases or reports.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]

# Keep compatibility imports and data collection consistent across all builds.
# --clean is opt-in for local rebuilding; CI and releases reuse safe caches.
PYINSTALLER_ARGS = (
    "--paths", "src",
    "--onedir",
    "--noconfirm",
    "--console",
    "--name", "PenX",
    "--contents-directory", "_internal",
    "--hidden-import=penx_app.setup.first_run_setup",
    "--hidden-import=penx_app.setup.llm_setup",
    "--hidden-import=penx_app.setup.install_scanners_windows",
    "--hidden-import=whois",
    "--hidden-import=dns.resolver",
    "--collect-all", "reportlab",
    "--collect-all", "ddgs",
    "--collect-all", "dns",
    "--collect-all", "jsonschema",
    "--collect-all", "defusedxml",
    "--hidden-import=debian.debian_support",
    "--hidden-import=rpm_vercmp",
)


def build_command(*, clean: bool = False) -> list[str]:
    """Return an argument vector, never a shell command string."""
    flags = ["--clean"] if clean else []
    return [sys.executable, "-m", "PyInstaller", *PYINSTALLER_ARGS,
            *flags, "penx.py"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build the PenX Windows portable folder with PyInstaller."
    )
    parser.add_argument("--clean", action="store_true",
                        help="Remove cached PyInstaller analysis for a local rebuild")
    args = parser.parse_args(argv)
    try:
        result = subprocess.run(build_command(clean=args.clean),
                                cwd=ROOT, check=False)
    except OSError as exc:
        print(f"[FAIL] Could not launch PyInstaller: {exc}", file=sys.stderr)
        return 1
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
