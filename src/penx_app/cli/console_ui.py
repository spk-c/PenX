"""Dependency-free terminal badges for PenX on Windows and POSIX terminals."""
from __future__ import annotations

import os
import sys

_COLORS = {
    "critical": "91", "high": "91", "medium": "93",
    "low": "92", "info": "96", "unknown": "90",
}


def _can_color() -> bool:
    return sys.stdout.isatty() and "NO_COLOR" not in os.environ


def badge(severity: str) -> str:
    name = str(severity or "unknown").lower()
    label = f"[{name.upper()}]"
    code = _COLORS.get(name, "90")
    return f"\033[{code}m{label}\033[0m" if _can_color() else label


def phase(label: str, message: str = "") -> None:
    prefix = f"  [ {label.upper()} ]"
    if _can_color():
        prefix = f"\033[95m{prefix}\033[0m"
    print(prefix + ("  " + message if message else ""), flush=True)
