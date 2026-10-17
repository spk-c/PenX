"""Pure scanner menu choice policy; no terminal, IO, network or DB access."""
from __future__ import annotations

from collections.abc import Iterable
from penx_app.domain.scan_models import ReconChoice


def resolve_scanner_selection(choice: str, menu_keys: Iterable[str]) -> tuple[str, ...] | ReconChoice | None:
    """Normalize requested scanner IDs while preserving preset order.

    Caller handles navigation cancellation, active-scan consent and adapter
    execution. Unknown or mixed passive choices never launch scanners.
    """
    choice = choice.strip().lower()
    keys_available = tuple(menu_keys)
    if choice == "0":
        return ReconChoice.PASSIVE_ONLY
    keys = choice.replace(",", " ").split()
    if "0" in keys:
        return None
    presets = {
        "a": ("1", "2", "3", "4", "5"),
        "n": ("1", "2", "3", "4", "5", "6"),
        # Extended multi-tool mapping is intentionally not an automatic
        # part of the full preset. It needs an explicit per-session choice.
        "x": tuple(key for key in keys_available if key != "e"),
    }
    chosen = presets[choice] if choice in presets else tuple(keys)
    if not chosen or any(key not in keys_available for key in chosen):
        return None
    return tuple(dict.fromkeys(chosen))
