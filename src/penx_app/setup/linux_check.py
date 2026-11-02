"""Offline Linux diagnostics. No target scans or package installation."""
from __future__ import annotations

import os
import platform
import sys
from penx_app.app_paths import APP_ROOT
from penx_app.setup.first_run_setup import scanner_status


def main() -> int:
    if os.name == "nt":
        raise RuntimeError("Use Windows diagnostics on Windows")
    print(f"PenX Linux diagnostics | {platform.platform()}")
    print(f"Python: {sys.version.split()[0]}")
    print(f"User data: {APP_ROOT}")
    print("Scanner presence (not proof of a successful scan):")
    for name, found in scanner_status().items():
        print(f"  [{'OK' if found else 'MISSING'}] {name}")
    print("Missing external tools are optional. See LINUX.md.")
    return 0
