"""Scope interactive Ctrl+C to cooperative scanner cancellation.

Only a process's main thread can install SIGINT handlers. A first Ctrl+C
marks an event consumed by scanner adapters; a second remains an emergency
interrupt. The prior handler is always restored on normal exit or failure.
"""
from __future__ import annotations

from contextlib import contextmanager
import signal
import threading
from collections.abc import Iterator


@contextmanager
def scanner_cancellation() -> Iterator[threading.Event]:
    """Yield a fresh scan-local token; never change global handlers permanently."""
    event = threading.Event()
    if threading.current_thread() is not threading.main_thread():
        # Non-main-thread callers can still use the token programmatically.
        yield event
        return

    previous = signal.getsignal(signal.SIGINT)

    def on_interrupt(_signum: int, _frame: object) -> None:
        if event.is_set():
            raise KeyboardInterrupt
        event.set()

    try:
        signal.signal(signal.SIGINT, on_interrupt)
    except (OSError, ValueError):
        # Some embedded consoles restrict signal handler installation.
        # Their normal Ctrl+C behavior still triggers process-tree cleanup.
        yield event
        return
    try:
        yield event
    finally:
        signal.signal(signal.SIGINT, previous)
