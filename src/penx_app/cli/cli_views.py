"""Pure CLI presentation utilities for PenX.

Existing penx.py function names remain compatible for scripts and tests.
"""
from __future__ import annotations
import sys


def banner():
    if sys.stdout.isatty():
        print("\x1b[2J\x1b[H", end="")
    print("""
\033[95m
    ██████╗ ███████╗███╗   ██╗██╗  ██╗
    ██╔══██╗██╔════╝████╗  ██║╚██╗██╔╝
    ██████╔╝█████╗  ██╔██╗ ██║ ╚███╔╝
    ██╔═══╝ ██╔══╝  ██║╚██╗██║ ██╔██╗
    ██║     ███████╗██║ ╚████║██╔╝ ██╗
    ╚═╝     ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝
\033[0m
    \033[90mPenX | AI Security Assessment | Local LLM | Windows 10/11\033[0m
    \033[90m────────────────────────────────────────────────────────────\033[0m
""")


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────


def divider(label=""):
    if label:
        print(f"\n\033[33m{'─'*20} {label} {'─'*20}\033[0m")
    else:
        print(f"\033[90m{'─'*60}\033[0m")


def success(text):
    print(f"\033[92m[+] {text}\033[0m")


def warn(text):
    print(f"\033[93m[!] {text}\033[0m")


def error(text):
    print(f"\033[91m[✗] {text}\033[0m")


def info(text):
    print(f"\033[94m[*] {text}\033[0m")


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
