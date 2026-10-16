"""Per-context runtime options, with a legacy environment fallback."""
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
import os


@dataclass
class RuntimeOptions:
    live_output: bool = False


_options: ContextVar[RuntimeOptions | None] = ContextVar('penx_runtime_options', default=None)


def live_output() -> bool:
    options = _options.get()
    return options.live_output if options is not None else os.getenv(
        'PENX_LIVE_OUTPUT', '0').lower() in ('1', 'on', 'true', 'yes')


@contextmanager
def runtime_options(options: RuntimeOptions):
    token = _options.set(options)
    try:
        yield options
    finally:
        _options.reset(token)


def toggle_live_output() -> bool:
    options = _options.get()
    if options is None:
        options = RuntimeOptions(live_output())
        _options.set(options)
    options.live_output = not options.live_output
    return options.live_output
