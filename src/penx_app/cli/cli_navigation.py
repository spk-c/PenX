"""Shared Back navigation for PenX's interactive terminal menus.

In a real console, Esc returns immediately without Enter. Non-interactive
stdin (automation, redirected input) retains standard input() behavior.
Only selection prompts use navigation_input; free-text editing remains input().
"""
from __future__ import annotations

import os
import sys


BACK_CHOICES = frozenset(("0", "b", "back"))
_ESC = "\x1b"


def is_back(value: str) -> bool:
    """Recognize typed aliases and the raw escape key."""
    return str(value).strip().casefold() in BACK_CHOICES or value == _ESC


def show_back(label: str = "Back to main menu") -> None:
    """Show Back as a menu item; typed aliases remain accepted by is_back."""
    print(f"  \033[92m[Esc]\033[0m  {label}")


def _read_chars(prompt: str, getch, *, posix_fd: int | None = None) -> str:
    """Minimal editable console input; read Esc immediately, not after Enter."""
    print(prompt, end="", flush=True)
    chars: list[str] = []
    try:
        while True:
            ch = getch()
            if not ch:
                raise EOFError
            if ch in ("\x00", "\xe0"):  # Windows extended scan code, not Escape
                getch()
                continue
            if ch == _ESC:
                if posix_fd is not None:
                    # Arrow/function keys begin with ESC [ ... or ESC O ...
                    # Consume such a sequence without treating it as Back.
                    import select
                    if select.select([posix_fd], [], [], 0.05)[0]:
                        suffix = os.read(posix_fd, 1)
                        if suffix in (b"[", b"O"):
                            for _ in range(16):
                                if not select.select([posix_fd], [], [], 0.02)[0]:
                                    break
                                code = os.read(posix_fd, 1)
                                if code and 0x40 <= code[0] <= 0x7e:
                                    break
                            continue
                print(flush=True)
                return "back"
            if ch in ("\r", "\n"):
                print(flush=True)
                return "".join(chars)
            if ch in ("\b", "\x7f"):
                if chars:
                    chars.pop()
                    print("\b \b", end="", flush=True)
                continue
            if ch == "\x03":  # Ctrl+C
                raise KeyboardInterrupt
            if ch == "\x04":  # Ctrl+D
                raise EOFError
            if ch.isprintable() and len(chars) < 2048:
                chars.append(ch)
                print(ch, end="", flush=True)
    except (KeyboardInterrupt, EOFError):
        print(flush=True)
        raise


def _read_windows(prompt: str) -> str:
    import msvcrt
    # Resolve this Windows-only API dynamically: the Linux type stub for
    # msvcrt cannot expose getwch, but native Windows consoles provide it.
    return _read_chars(prompt, getattr(msvcrt, "getwch"))


def _read_posix(prompt: str) -> str:
    """Unix terminal: cbreak with echo disabled, restored even on Esc/Ctrl+C."""
    import codecs
    import termios
    import tty

    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    decoder = codecs.getincrementaldecoder(sys.stdin.encoding or "utf-8")("replace")

    def getch() -> str:
        while True:
            byte = os.read(fd, 1)
            if not byte:
                raise EOFError
            char = decoder.decode(byte)
            if char:
                return char

    try:
        tty.setcbreak(fd)
        mode = termios.tcgetattr(fd)
        mode[3] &= ~termios.ECHO
        termios.tcsetattr(fd, termios.TCSADRAIN, mode)
        return _read_chars(prompt, getch, posix_fd=fd)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)


def navigation_input(prompt: str) -> str:
    """Get a menu selection; Esc immediately returns 'back' on an interactive TTY.

    stdin pipes, CI, IDE consoles without a TTY and mocks continue using
    builtins.input(), preserving existing scripted behavior.
    """
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        return input(prompt)
    if os.name == "nt":
        try:
            return _read_windows(prompt)
        except (ImportError, OSError):
            return input(prompt)
    if os.name == "posix":
        try:
            return _read_posix(prompt)
        except (ImportError, OSError, ValueError):
            return input(prompt)
    return input(prompt)
