"""Cooperative outbound-request limiter for project-bound safe adapters.

The limit is shared by one project-bound scan. Standalone scans have no
project limiter; no global monkeypatch of socket or subprocess is used.
"""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from threading import Event, Lock
import time
from collections.abc import Iterator


class ProjectRateLimiter:
    def __init__(self, requests_per_second: float):
        if not 0 < requests_per_second <= 60:
            raise ValueError('Project rate must be in (0, 60] requests/second.')
        self.interval = 1.0 / requests_per_second
        self._lock = Lock()
        self._next = 0.0

    def acquire(self, cancel_event: Event | None = None) -> None:
        # A single project-bound scan is sequential (max_parallelism=1).
        # Reserve the next slot under a lock; do not hold it while sleeping.
        with self._lock:
            now = time.monotonic()
            start = max(now, self._next)
            self._next = start + self.interval
        wait = start - time.monotonic()
        if wait > 0:
            if cancel_event is not None:
                if cancel_event.wait(wait):
                    raise InterruptedError('Project scan cancelled before outbound I/O.')
            else:
                time.sleep(wait)
        if cancel_event is not None and cancel_event.is_set():
            raise InterruptedError('Project scan cancelled before outbound I/O.')


_ACTIVE: ContextVar[ProjectRateLimiter | None] = ContextVar(
    'penx_project_rate_limiter', default=None)


@contextmanager
def project_rate_context(limiter: ProjectRateLimiter | None) -> Iterator[None]:
    token = _ACTIVE.set(limiter)
    try:
        yield
    finally:
        _ACTIVE.reset(token)


def project_rate_before_io(cancel_event: Event | None = None) -> None:
    limiter = _ACTIVE.get()
    if limiter is not None:
        limiter.acquire(cancel_event)
