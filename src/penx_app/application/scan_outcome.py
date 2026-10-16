"""Terminal-independent result of a single interactive scan attempt.

The UI decides whether to acknowledge diagnostics from this outcome, rather
than reading state left by a previous scan. A cancelled scanner menu does
not need acknowledgement, but a failed/incomplete attempted scan does.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ScanOutcome:
    completed: bool
    acknowledge: bool
    stage: str
    session_id: int | None = None

    def __post_init__(self) -> None:
        if self.completed and (not self.acknowledge or self.stage != "completed"):
            raise ValueError("Completed scan must be acknowledged as completed")
        if self.session_id is not None and self.session_id < 1:
            raise ValueError("Invalid reserved session ID")
