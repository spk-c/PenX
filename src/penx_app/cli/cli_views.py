"""Pure CLI presentation utilities for PenX.

Existing penx.py function names remain compatible for scripts and tests.
ANSI escapes are only emitted when the terminal supports color; redirected
(plain) output stays escape-free and ASCII-safe.
"""
from __future__ import annotations

from penx_app.cli import terminal

_BANNER_ART = (
    "    ██████╗ ███████╗███╗   ██╗██╗  ██╗\n"
    "    ██╔══██╗██╔════╝████╗  ██║╚██╗██╔╝\n"
    "    ██████╔╝█████╗  ██╔██╗ ██║ ╚███╔╝\n"
    "    ██╔═══╝ ██╔══╝  ██║╚██╗██║ ██╔██╗\n"
    "    ██║     ███████╗██║ ╚████║██╔╝ ██╗\n"
    "    ╚═╝     ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝"
)
_BANNER_SUBTITLE = "PenX | AI Security Assessment | Local LLM | Windows 10/11"
_RULE = "─" * 60


def banner():
    caps = terminal.detect_capabilities()
    if caps.interactive and not caps.plain:
        print("\x1b[2J\x1b[H", end="")
    if caps.plain:
        print(_BANNER_SUBTITLE)
        print("-" * 60)
        return
    if caps.color:
        print(f"\n\033[95m\n{_BANNER_ART}\n\033[0m\n"
              f"    \033[90m{_BANNER_SUBTITLE}\033[0m\n    \033[90m{_RULE}\033[0m\n")
    else:
        print(f"\n{_BANNER_ART}\n\n    {_BANNER_SUBTITLE}\n    {_RULE}\n")


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────


def divider(label=""):
    caps = terminal.detect_capabilities()
    if label:
        line = f"{'─' * 20} {label} {'─' * 20}"
        if caps.plain:
            print(f"\n{'-' * 20} {label} {'-' * 20}")
        elif caps.color:
            print(f"\n\033[33m{line}\033[0m")
        else:
            print(f"\n{line}")
    elif caps.plain:
        print("-" * 60)
    elif caps.color:
        print(f"\033[90m{_RULE}\033[0m")
    else:
        print(_RULE)


def success(text):
    line = f"[+] {text}"
    if terminal.detect_capabilities().color:
        line = f"\033[92m{line}\033[0m"
    print(line)


def warn(text):
    line = f"[!] {text}"
    if terminal.detect_capabilities().color:
        line = f"\033[93m{line}\033[0m"
    print(line)


def error(text):
    mark = "✗" if terminal.detect_capabilities().color else "x"
    line = f"[{mark}] {text}"
    if terminal.detect_capabilities().color:
        line = f"\033[91m{line}\033[0m"
    print(line)


def info(text):
    line = f"[*] {text}"
    if terminal.detect_capabilities().color:
        line = f"\033[94m{line}\033[0m"
    print(line)


def is_active_session(history) -> bool:
    """History tuple layout: (sl_no, target, scan_date, status)."""
    return bool(history and len(history) >= 4 and history[3] == "active")


def format_vulnerability_picker(row: tuple) -> str:
    """Use canonical DB columns, tolerating abbreviated legacy/test rows."""
    confidence = row[4] if len(row) > 4 else "-"
    port = row[5] if len(row) > 5 else "-"
    service = row[6] if len(row) > 6 else "-"
    return (f"  id={row[0]} | {row[2]} | {row[3]} | "
            f"Confidence: {confidence} | Port: {port} | Service: {service}")
