"""Versioned machine-readable reason codes for terminal scanner outcomes.

`diagnostics` remains free human text; `reason` is the stable code that
TUI/CLI/JSON/SARIF/history/AI consumers can rely on without string matching.
The vocabulary is closed: extending it requires a new REASON_VERSION and an
additive metadata migration, never a silent reuse of an existing code.
"""
from __future__ import annotations

REASON_VERSION = 1

REASON_CODES = (
    'missing_dependency',  # Executable or optional library not installed.
    'timeout',             # Process/node/global time budget exhausted.
    'cancelled',           # Caller requested a stop before or during I/O.
    'truncated',           # Captured or rendered data bounded; loss explicit.
    'scope_denied',        # Consent or scope blocked the adapter.
    'parse_invalid',       # Scanner output could not be parsed or decoded.
    'partial',             # Incomplete outcome without a specific code.
    'error',               # Adapter exception or nonzero exit.
    'skipped',             # Not started (prerequisite, overload, schedule).
)


def is_valid_reason(reason: str | None) -> bool:
    """Closed-set membership check shared by all outcome boundaries."""
    return reason is None or reason in REASON_CODES
