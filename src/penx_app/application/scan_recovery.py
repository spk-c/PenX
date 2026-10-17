"""Fail-safe local recovery of scanner evidence and unfinished assessments.

Recovery snapshots must never be published before their full content has
been written, flushed and synced. Use the same no-overwrite atomic staging
facility as normal exports; no database writes or network access.
"""
from __future__ import annotations

import json
from pathlib import Path

from penx_app.file_output import publish_unique


def _session_id(value: int) -> int:
    # These filenames are not target-controlled and must stay within reports.
    if type(value) is not int or value <= 0:
        raise ValueError("Recovery session ID must be a positive integer.")
    return value


def save_unanalysed_recon(root: Path, session_id: int, raw_scan: str):
    """Keep complete evidence apart from assessed sessions on LLM failure.

    Never leave a misleading partial recovery file after an interrupted
    write, an encoding error, or a storage failure.
    """
    sid = _session_id(session_id)
    if not isinstance(raw_scan, str):
        raise TypeError("Recovery scanner output must be text.")
    return publish_unique(
        Path(root) / "reports", f"recon_SL{sid}_unanalysed", ".txt",
        raw_scan,
    )


def save_unsaved_assessment(root: Path, session_id: int, result: dict, *,
                            notify=None):
    """Keep complete, uncommitted model output without overwriting a retry."""
    sid = _session_id(session_id)
    if not isinstance(result, dict):
        raise TypeError("Unsaved assessment must be an object.")
    # Serialize before creating any persistent recovery path. A circular
    # reference or invalid string must not leave an incomplete JSON file.
    payload = json.dumps(result, ensure_ascii=False, indent=2, default=str)
    output = publish_unique(
        Path(root) / "reports", f"assessment_SL{sid}_unsaved", ".json",
        payload,
    )
    if notify is not None:
        notify(f"Unsaved model assessment preserved locally: {output}")
    return output
