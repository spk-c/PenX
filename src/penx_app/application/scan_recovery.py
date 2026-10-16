"""Fail-safe local recovery of scanner evidence and unfinished assessments.

Uses exclusive creation and owner-readable files without database writes.
"""
from __future__ import annotations
import os
from pathlib import Path


def save_unanalysed_recon(root: Path, session_id: int, raw_scan: str):
    """Keep read-only evidence separate from valid assessed sessions on LLM failure."""
    directory = root / "reports"
    directory.mkdir(parents=True, exist_ok=True)
    # Exclusive files never overwrite existing evidence, including on retries.
    for attempt in range(101):
        suffix = "" if attempt == 0 else f"_{attempt}"
        output = directory / f"recon_SL{session_id}_unanalysed{suffix}.txt"
        try:
            fd = os.open(str(output), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            continue
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(raw_scan)
        return output
    raise FileExistsError(f"Too many evidence files for SL#{session_id}")


def save_unsaved_assessment(root: Path, session_id: int, result: dict, *, notify=None):
    """Save uncommitted model output for recovery without overwriting earlier attempts."""
    import json

    directory = root / "reports"
    directory.mkdir(parents=True, exist_ok=True)
    for attempt in range(101):
        suffix = "" if attempt == 0 else f"_{attempt}"
        output = directory / f"assessment_SL{session_id}_unsaved{suffix}.json"
        try:
            fd = os.open(str(output), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            continue
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(result, handle, ensure_ascii=False, indent=2, default=str)
        if notify is not None:
            notify(f"Unsaved model assessment preserved locally: {output}")
        return output
    raise FileExistsError(f"Too many unsaved assessment files for SL#{session_id}")
