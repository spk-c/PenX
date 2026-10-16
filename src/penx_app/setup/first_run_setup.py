"""Opt-in first-launch scanner setup for portable Windows PenX builds.

The EXE includes the Python app, not third-party scanner executables.
Keep downloads and UAC prompts in the existing verified Windows installer;
never install software silently or run network operations for smoke tests.
"""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import sys

from penx_app.app_paths import APP_ROOT
from penx_app.settings import environment_values
from penx_app.scanners.scanner_runtime import find_nmap, find_runtime, npcap_present
from penx_app.scanners.native_web_scanners import find_native
# Static import deliberately keeps this installer inside PyInstaller --onedir.
from penx_app.setup import install_scanners_windows

FIRST_RUN_MARKER = APP_ROOT / "data" / ".scanner-setup-offered"
_scanner_env = environment_values(os.environ, APP_ROOT / '.env')


def _path_setting(name, default):
    return _scanner_env.get('PENX_' + name, _scanner_env.get('METATRON_' + name, default))


NMAP_PATH = _path_setting('NMAP_PATH', '')
WHATWEB_PATH = _path_setting('WHATWEB_PATH', str(APP_ROOT / 'vendor' / 'whatweb' / 'whatweb'))
NIKTO_PATH = _path_setting('NIKTO_PATH', str(APP_ROOT / 'vendor' / 'nikto' / 'program' / 'nikto.pl'))


def _present(check, *args):
    try:
        return bool(check(*args))
    except OSError:
        return False


def is_windows() -> bool:
    return os.name == "nt"


def scanner_status() -> dict[str, bool]:
    """Quick, local presence checks only. No downloads, scans or subprocesses."""
    return {
        "Nmap": bool(find_nmap(NMAP_PATH)),
        "Npcap": npcap_present() if is_windows() else False,
        "Ruby": bool(find_runtime("ruby")),
        "WhatWeb": _present(Path(WHATWEB_PATH).is_file),
        "Strawberry Perl": bool(find_runtime("perl")),
        "Nikto": _present(Path(NIKTO_PATH).is_file),
        "Nuclei": bool(find_native("nuclei")),
        "ProjectDiscovery httpx": bool(find_native("httpx")),
        "ffuf": bool(find_native("ffuf")),
        "Subfinder": bool(find_native("subfinder")),
        "Katana": bool(find_native("katana")),
    }


def missing_scanners() -> list[str]:
    return [name for name, present in scanner_status().items() if not present]


def print_status() -> None:
    print("PenX scanner components (presence checks, not full compatibility tests):")
    for name, present in scanner_status().items():
        print(f"  [{'OK' if present else 'MISSING'}] {name}")
    print("Use PenX.exe --setup to install or repair all scanner components.")
    print("Use PenX.exe --setup-native to install Nuclei, httpx, ffuf, Subfinder and Katana.")


def ensure_private_env() -> None:
    """Create a user-editable configuration only if one does not exist."""
    target = APP_ROOT / ".env"
    template = APP_ROOT / ".env.example"
    if not template.is_file() and getattr(sys, "frozen", False):
        # The installed edition keeps read-only templates under Program Files
        # (or per-user Programs) but stores private settings under LocalAppData.
        template = Path(sys.executable).resolve().parent / ".env.example"
    if target.exists():
        return
    if not template.is_file():
        print("[WARN] .env.example not found. Configure a private .env manually.")
        return
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        # Do not overwrite an existing private configuration, including races.
        with template.open("rb") as source, target.open("xb") as destination:
            shutil.copyfileobj(source, destination)
    except FileExistsError:
        return
    except OSError as exc:
        print(f"[WARN] Could not create private PenX .env: {exc}")
        return
    print("[INFO] Created .env from .env.example. Configure your own local LLM model.")


def mark_offered() -> None:
    try:
        FIRST_RUN_MARKER.parent.mkdir(parents=True, exist_ok=True)
        FIRST_RUN_MARKER.write_text(
            "Scanner setup was offered. Use PenX.exe --setup to rerun.\n",
            encoding="utf-8",
        )
    except OSError as exc:
        print(f"[WARN] Could not save first-run state: {exc}")


def run_setup(*, force: bool = False) -> int:
    """Offer missing third-party scanners on first EXE start; never block normal use.

    Explicit --setup can be used later regardless of the first-run marker.
    Returns a nonzero status only when the explicit installer fails.
    """
    if not is_windows():
        if force:
            print("[ERROR] The scanner installer is for Windows 10/11.")
            return 2
        return 0
    if not force and not getattr(sys, "frozen", False):
        # The source installation already has install-windows.bat.
        return 0

    ensure_private_env()
    if not force and FIRST_RUN_MARKER.exists():
        return 0

    missing = missing_scanners()
    if not missing:
        print("[OK] All external scanner components were found.")
        mark_offered()
        return 0

    print("\nPenX first-run scanner setup")
    print("Missing: " + ", ".join(missing))
    print("PenX can install Nmap/Npcap, Ruby/WhatWeb, Perl/Nikto,")
    print("Nuclei, ProjectDiscovery httpx, ffuf, Subfinder and Katana.")
    print("This downloads software from official sources and may require")
    print("an internet connection, Windows UAC approval and interactive installers.")
    print("Nmap's installer is SHA-256 checked before execution.")
    print("No scanner will run during setup. You can keep using PenX without these tools.")
    try:
        consent = input("Install missing scanner components now? [y/N]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print("\n[INFO] Scanner setup skipped.")
        mark_offered()
        return 0
    if consent not in ("y", "yes"):
        print("[INFO] Scanner setup skipped. Run PenX.exe --setup later.")
        mark_offered()
        return 0

    try:
        result = install_scanners_windows.main([])
    except (Exception, KeyboardInterrupt) as exc:
        print(f"[WARN] Scanner installation interrupted or failed: {exc}")
        result = 1

    remaining = missing_scanners()
    if remaining or result:
        print("[WARN] Some scanner components are still unavailable: "
              + (", ".join(remaining) if remaining else "check installer output"))
        print("[INFO] Retry later with PenX.exe --setup.")
    else:
        print("[OK] External scanner setup completed.")
    mark_offered()
    return 1 if (remaining or result) and force else 0
