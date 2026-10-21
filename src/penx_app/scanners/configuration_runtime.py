"""Adapter-local configuration, isolated across parallel worker contexts."""
from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from collections.abc import Iterator

from penx_app.domain.scanner_configuration import ScannerConfiguration

_CURRENT: ContextVar[ScannerConfiguration | None] = ContextVar('penx_scanner_configuration', default=None)


@contextmanager
def configured_adapter(options: ScannerConfiguration) -> Iterator[None]:
    token = _CURRENT.set(options)
    try:
        yield
    finally:
        _CURRENT.reset(token)


def external_options(command: list[str], timeout: int) -> tuple[list[str], int]:
    options = _CURRENT.get()
    if options is None:
        return command, timeout
    args = list(command)
    if options.timeout_seconds is not None:
        timeout = options.timeout_seconds
    if options.ports:
        # Only the Nmap adapter can carry a ports option; no shell is used.
        args[1:1] = ['-p', ','.join(str(port) for port in options.ports)]
    if options.severities:
        args[args.index('-severity') + 1] = ','.join(options.severities)
    if options.rate_limit is not None:
        flag = '-rate' if options.scanner_key == '9' else '-rl'
        args[args.index(flag) + 1] = str(options.rate_limit)
    return args, timeout
