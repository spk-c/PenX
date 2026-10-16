"""Immutable reviewed report projection shared by interactive and machine exports.

Renderer inputs come from an existing saved session. This module neither
fetches data nor probes a target, and keeps rejected corrections in the source
snapshot for auditability while filtering presentation-only rows.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from penx_app.domain.finding_policy import active_vulnerabilities


@dataclass(frozen=True)
class ReportView:
    source: Mapping[str, Any]
    active_findings: tuple[tuple, ...]
    active_fixes: tuple[tuple, ...]

    @classmethod
    def from_session(cls, data: Mapping[str, Any]) -> "ReportView":
        active = tuple(active_vulnerabilities(dict(data)))
        ids = {row[0] for row in active}
        fixes = tuple(row for row in data.get("fixes", ()) or () if row[2] in ids)
        return cls(data, active, fixes)

    def as_legacy(self) -> dict:
        """Provide the existing dict API while keeping the input unchanged."""
        return {**self.source, "vulns": list(self.active_findings),
                "fixes": list(self.active_fixes)}
