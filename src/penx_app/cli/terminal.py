"""Terminal capability detection and plain-mode text helpers for PenX.

Resolves interactive, color and plain output mode from the live stream and
the documented environment conventions:

- ``NO_COLOR`` (any value): disable ANSI color output.
- ``TERM=dumb``: force the screen-reader friendly plain mode.
- ``PENX_PLAIN`` (``1``/``on``/``true``/``yes``): force plain mode.
- ``COLUMNS``: explicit terminal width override.

Redirected (non-interactive) output is always plain: no ANSI escapes and a
fixed 80-column wrapping width, so logs and non-interactive runs stay clean
and ANSI never leaks into captured stdout.
"""
from __future__ import annotations

import os
import re
import shutil
import sys
from dataclasses import dataclass
from typing import Any, Mapping

DEFAULT_WIDTH = 80
_TRUE_VALUES = ("1", "on", "true", "yes")
_ANSI_RE = re.compile(r"\033\[[0-9;]*m")
_TOKEN_RE = re.compile(r"\S+|\s+")


@dataclass(frozen=True)
class TerminalCapabilities:
    """Resolved output mode for the current terminal.

    ``interactive`` is True only when stdout is a TTY. ``color`` is True only
    for a TTY without ``NO_COLOR``, ``TERM=dumb`` or ``PENX_PLAIN``. ``plain``
    is True whenever color output must be stripped: explicit opt-in, dumb
    terminals and any redirected/piped stream. ``width`` is the visible
    column budget for wrapping.
    """

    interactive: bool
    color: bool
    plain: bool
    width: int


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in _TRUE_VALUES


def _is_tty(stream: Any) -> bool:
    try:
        return bool(stream.isatty())
    except (AttributeError, ValueError, OSError):
        return False


def _resolve_width(environ: Mapping[str, str], stream: Any,
                   interactive: bool) -> int:
    try:
        columns = int(str(environ.get("COLUMNS", "")).strip())
    except ValueError:
        columns = 0
    if columns > 0:
        return columns
    if interactive:
        try:
            return shutil.get_terminal_size().columns
        except OSError:
            pass
    return DEFAULT_WIDTH


def detect_capabilities(stream: Any = None,
                        environ: Mapping[str, str] | None = None) -> TerminalCapabilities:
    """Resolve terminal capabilities from *stream* and *environ*.

    Defaults to ``sys.stdout`` and ``os.environ``; both can be overridden for
    deterministic tests.
    """
    stream = sys.stdout if stream is None else stream
    env: Mapping[str, str] = os.environ if environ is None else environ
    interactive = _is_tty(stream)
    no_color = "NO_COLOR" in env
    dumb = str(env.get("TERM", "")).strip().lower() == "dumb"
    plain = _truthy(env.get("PENX_PLAIN")) or dumb or not interactive
    color = interactive and not no_color and not plain
    width = _resolve_width(env, stream, interactive)
    return TerminalCapabilities(
        interactive=interactive, color=color, plain=plain, width=width)


def visible_length(text: str) -> int:
    """Count characters excluding ANSI escape sequences."""
    return len(_ANSI_RE.sub("", text))


def _hard_split(token: str, width: int) -> list[str]:
    """Split a too-long token, keeping escape sequences with their char."""
    parts: list[str] = []
    current = ""
    pending = ""
    visible = 0
    index = 0
    while index < len(token):
        match = _ANSI_RE.match(token, index)
        if match:
            pending += match.group(0)
            index = match.end()
            continue
        char = token[index]
        index += 1
        if visible >= width:
            parts.append(current)
            current = ""
            visible = 0
        current += pending + char
        pending = ""
        visible += 1
    current += pending
    if current:
        parts.append(current)
    return parts


def wrap_text(text: str, width: int) -> str:
    """Wrap *text* at a visible *width*, keeping ANSI escapes intact.

    Breaks on word boundaries; words longer than *width* are hard-split.
    Escape sequences are zero-width and are never separated from the
    character they style. Existing newlines are preserved.
    """
    width = max(1, int(width))
    lines: list[str] = []
    current = ""
    visible = 0
    for token in _TOKEN_RE.findall(text):
        token_width = visible_length(token)
        if token.isspace():
            if current and visible + token_width <= width:
                current += token
                visible += token_width
            continue
        if token_width == 0:
            current += token
            continue
        if token_width > width:
            if current:
                lines.append(current.rstrip())
                current = ""
                visible = 0
            pieces = _hard_split(token, width)
            lines.extend(pieces[:-1])
            current = pieces[-1]
            visible = visible_length(current)
            continue
        if current and visible + token_width > width:
            lines.append(current.rstrip())
            current = ""
            visible = 0
        current += token
        visible += token_width
    if current:
        lines.append(current.rstrip())
    return "\n".join(lines)
