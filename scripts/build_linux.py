#!/usr/bin/env python3
"""Build a portable Linux PenX executable without bundling third-party scanners.

Run on Linux with dependencies and PyInstaller installed. PyInstaller cannot
cross-compile; run one build per target architecture.
"""
from __future__ import annotations

import argparse
import os
import shutil
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
PYINSTALLER_ARGS = (
    "--paths", "src",
    "--onedir", "--noconfirm", "--console",
    "--name", "PenX",
    "--contents-directory", "_internal",
    "--hidden-import=penx_app.setup.linux_check",
    "--hidden-import=penx_app.setup.llm_setup",
    "--hidden-import=whois",
    "--collect-data=whois",
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
    flags = ["--clean"] if clean else []
    return [sys.executable, "-m", "PyInstaller", *PYINSTALLER_ARGS,
            *flags, "penx.py"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build PenX for the host Linux platform")
    parser.add_argument("--clean", action="store_true")
    args = parser.parse_args(argv)
    if sys.platform != "linux" or os.name != "posix":
        print("Linux packages must be built on a Linux host", file=sys.stderr)
        return 2
    try:
        result = subprocess.run(build_command(clean=args.clean), cwd=ROOT, check=False)
        if result.returncode:
            return result.returncode
        # PyInstaller puts --add-data inside _internal, but the installer
        # reads the template beside the executable in read-only /opt/penx.
        destination = ROOT / "dist" / "PenX" / ".env.example"
        shutil.copyfile(ROOT / ".env.example", destination)
        return 0
    except OSError as exc:
        print(f"PyInstaller failed to launch: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
