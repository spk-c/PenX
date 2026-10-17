"""Safe, session-scoped HTML/PDF report generation and deletion.

Only PenX's two deterministic per-session filenames are managed here. A
session's database rows are never modified when deleting exported files.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import tempfile

from penx_app.app_paths import APP_ROOT
from penx_app.storage.db import get_session
from penx_app.reporting.export import export_html, export_pdf, add_saved_comparison


def report_paths(sl_no: int, target: str, directory: str | Path | None = None) -> dict[str, Path]:
    """Return only the exact report files belonging to this session/target."""
    if not isinstance(sl_no, int) or isinstance(sl_no, bool) or sl_no <= 0:
        raise ValueError("Invalid scan session ID.")
    safe = re.sub(r"[^A-Za-z0-9_-]+", "_", str(target))[:70].strip("_") or "target"
    folder = Path(directory) if directory is not None else APP_ROOT / "reports"
    base = f"penx_SL{sl_no}_{safe}"
    return {"html": folder / f"{base}.html", "pdf": folder / f"{base}.pdf"}


def existing_reports(sl_no: int, target: str,
                     directory: str | Path | None = None) -> dict[str, Path]:
    result = {}
    for kind, path in report_paths(sl_no, target, directory).items():
        # Never follow symlinks planted in the report folder.
        if path.is_symlink():
            raise OSError(f"Report path is a symbolic link and cannot be managed: {path.name}")
        if path.is_file():
            result[kind] = path
    return result



def publication_status(sl_no: int, target: str, *,
                       directory: str | Path | None = None) -> str | None:
    """Read-only, session-scoped manifest status for the history view.

    A manifest is only advisory; never infer the existence or correctness
    of exported files from its status alone. Reject non-regular metadata.
    """
    from penx_app.reporting.report_batch import _manifest_path, publication_state
    folder = report_paths(sl_no, target, directory)["html"].parent
    manifest = _manifest_path(folder, sl_no)
    if manifest.is_symlink() or (manifest.exists() and not manifest.is_file()):
        raise OSError(f"Invalid report publication manifest: {manifest.name}")
    state = publication_state(folder, sl_no)
    if (not isinstance(state, dict)
            or state.get("schema") != "penx-publication-v1"
            or type(state.get("session")) is not int
            or state.get("session") != sl_no):
        return None
    status = state.get("status")
    return status if status in {"in_progress", "partial", "complete"} else None


def generate_session_reports(sl_no: int, *, directory: str | Path | None = None) -> dict[str, Path]:
    """Generate HTML + PDF only for a completed, saved assessment.

    Both formats are built inside a temporary folder first, so an export
    failure never publishes a half-written new report or damages the DB.
    The caller handles OSError/ReportLab errors independently of scan commit.
    """
    data = get_session(sl_no)
    history = data.get("history")
    if not history or history[3] != "active" or not data.get("summary"):
        raise ValueError(f"SL#{sl_no} is not a completed assessment.")
    data = add_saved_comparison(data)
    output_paths = report_paths(sl_no, history[1], directory)
    folder = output_paths["html"].parent
    folder.mkdir(parents=True, exist_ok=True)
    for path in output_paths.values():
        if path.is_symlink():
            raise OSError(f"Refusing to overwrite report symlink: {path.name}")

    from penx_app.reporting.report_batch import (
        begin_publication, finalize_publication, validate_staged_report,
    )
    # Crash-detection marker: written before any report file is touched. A process
    # that dies before finalize leaves an in_progress manifest that a re-run
    # detects and completes (each individual file write is already atomic).
    begin_publication(folder, sl_no, ("html", "pdf"))

    try:
        with tempfile.TemporaryDirectory(prefix=f".penx_SL{sl_no}_", dir=str(folder)) as temporary:
            html = validate_staged_report(export_html(data, temporary), temporary)
            pdf = validate_staged_report(export_pdf(data, temporary), temporary)
            if html == pdf:
                raise OSError("HTML and PDF renderers returned the same staged file.")
            # Each replace is atomic on its own filesystem, not as a *pair*.
            # Snapshot both previous versions before touching either destination.
            # If publishing PDF fails after HTML succeeds, restore HTML (or remove
            # the newly created HTML when there was no earlier report).
            staged = {"html": html, "pdf": pdf}
            backups: dict[str, Path] = {}
            for kind, destination in output_paths.items():
                if destination.is_symlink():
                    raise OSError(f"Refusing to overwrite report symlink: {destination.name}")
                if destination.exists():
                    if not destination.is_file():
                        raise OSError(f"Report destination is not a regular file: {destination.name}")
                    backup = Path(temporary) / f".previous_{destination.name}"
                    shutil.copy2(destination, backup)
                    backups[kind] = backup
            published: list[str] = []
            try:
                for kind, destination in output_paths.items():
                    # Guard against a path changing after initial validation.
                    if destination.is_symlink():
                        raise OSError(f"Refusing to overwrite report symlink: {destination.name}")
                    os.replace(str(staged[kind]), str(destination))
                    published.append(kind)
            except OSError as exc:
                rollback_errors = []
                for kind in reversed(published):
                    destination = output_paths[kind]
                    try:
                        if destination.is_symlink():
                            raise OSError(f"Refusing to restore over symlink: {destination.name}")
                        if kind in backups:
                            os.replace(str(backups[kind]), str(destination))
                        else:
                            destination.unlink(missing_ok=True)
                    except OSError as rollback_exc:
                        rollback_errors.append(f"{destination.name}: {rollback_exc}")
                if rollback_errors:
                    # Backups in TemporaryDirectory are best-effort; do not hide
                    # an incomplete rollback as if the report pair were intact.
                    raise OSError(
                        f"Publishing reports failed ({exc}); rollback incomplete: "
                        + "; ".join(rollback_errors)
                    ) from exc
                raise
    except Exception as exc:
        # A recoverable renderer/IO failure is not a process crash. Keep the
        # original error and rollback behavior, but finalize the manifest.
        try:
            finalize_publication(
                folder, sl_no, {}, {"batch": f"{type(exc).__name__}: {exc}"},
            )
        except OSError:
            # Preserve the original failure; the in_progress marker still
            # provides a conservative signal that a re-run is needed.
            pass
        raise
    finalize_publication(folder, sl_no, output_paths, {})
    return output_paths



def generate_session_reports_independent(
    sl_no: int, *, directory: str | Path | None = None,
    formats: tuple[str, ...] = ("html", "pdf"),
):
    """Generate formats independently from the same committed session."""
    from penx_app.reporting.report_batch import publish_reports
    data = get_session(sl_no)
    history = data.get("history")
    if not history or history[3] != "active" or not data.get("summary"):
        raise ValueError(f"SL#{sl_no} is not a completed assessment.")
    data = add_saved_comparison(data)
    output_paths = report_paths(sl_no, history[1], directory)
    return publish_reports(
        data, output_paths["html"].parent, output_paths, formats=formats,
    )


def delete_session_reports(sl_no: int, target: str, *,
                           directory: str | Path | None = None) -> list[Path]:
    """Delete only that session's generated HTML/PDF, never other files/DB."""
    candidates = report_paths(sl_no, target, directory)
    from penx_app.reporting.report_batch import _manifest_path
    manifest = _manifest_path(candidates["html"].parent, sl_no)
    # Prevalidate every existing path BEFORE deleting any report or metadata.
    # A directory or symlink in one slot must not cause a partial deletion.
    for path in (*candidates.values(), manifest):
        if path.is_symlink() or (path.exists() and not path.is_file()):
            raise OSError(f"Refusing to delete non-regular report path: {path.name}")
    deleted = []
    for path in candidates.values():
        try:
            path.unlink()
        except FileNotFoundError:
            continue
        deleted.append(path)
    # Metadata contains report filenames (and potentially the scanned host).
    # Remove it only once both report-file deletions succeeded.
    manifest.unlink(missing_ok=True)
    return deleted
