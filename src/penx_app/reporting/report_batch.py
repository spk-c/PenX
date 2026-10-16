"""Independent publication results for already saved assessments.

No database, scanner or model imports. Every format is rendered and published
separately; a failure does not undo a different successfully published format.

Crash-detectable multi-file publication
---------------------------------------
Each multi-format batch is bracketed by an atomic, per-session publication
manifest (``.penx-publication_SL<session>.json`` in the output folder):

* ``begin_publication`` writes the manifest with ``status: "in_progress"``
  *before* any report file is touched (atomic temp-file + ``os.replace``).
* ``finalize_publication`` rewrites it with ``status: "complete"`` (every format
  published) or ``"partial"`` (the batch ran to completion but one or more
  formats failed) after the last format is handled.

A process crash between those two writes therefore leaves a detectable
``in_progress`` manifest. ``interrupted_publication`` reports that state, and a
caller recovers by simply re-running the same publication: every report write
is already atomic (``os.replace`` / ``os.link``) and the fresh manifest
replaces the stale one. The manifest is a hidden dotfile and never changes the
report filenames or formats.

Each individual file is atomically replaced, but the **pair is not a single
filesystem transaction**: HTML and PDF may temporarily show different versions
after a crash. Recovery is triggered by an explicit re-run of the publication;
a manifest alone does not automatically rerender reports at application startup.
The manifest is metadata, not a durability guarantee against power failure.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import tempfile
import uuid

_MANIFEST_SCHEMA = "penx-publication-v1"


def _manifest_path(folder: Path, session: int) -> Path:
    return Path(folder) / f".penx-publication_SL{int(session)}.json"


def _atomic_write_json(path: Path, payload: dict) -> Path:
    """Atomically publish ``payload`` as JSON at ``path`` (temp + os.replace)."""
    path = Path(path)
    contents = json.dumps(payload, ensure_ascii=False) + "\n"
    tmp = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", dir=str(path.parent), prefix=f"{path.name}.", suffix=".tmp",
            delete=False, encoding="utf-8",
        ) as stream:
            tmp = Path(stream.name)
            stream.write(contents)
        os.replace(str(tmp), str(path))
    finally:
        if tmp is not None and tmp.exists():
            tmp.unlink()
    return path


def begin_publication(folder: Path, session: int, formats: tuple[str, ...]) -> Path:
    """Atomically record that a multi-format publication has started."""
    path = _manifest_path(folder, session)
    path.parent.mkdir(parents=True, exist_ok=True)
    return _atomic_write_json(path, {
        "schema": _MANIFEST_SCHEMA,
        "session": int(session),
        "nonce": uuid.uuid4().hex,
        "status": "in_progress",
        "formats": list(formats),
        "created": {},
        "failed": {},
    })


def finalize_publication(folder: Path, session: int,
                         created: dict, failed: dict) -> Path:
    """Atomically mark a batch finished, recording per-format outcomes."""
    path = _manifest_path(folder, session)
    status = "partial" if failed else "complete"
    formats = list(created) + [fmt for fmt in failed if fmt not in created]
    return _atomic_write_json(path, {
        "schema": _MANIFEST_SCHEMA,
        "session": int(session),
        "status": status,
        "formats": formats,
        "created": {key: str(value) for key, value in created.items()},
        "failed": {key: str(value) for key, value in failed.items()},
    })


def publication_state(folder: Path, session: int) -> dict | None:
    """Return the recorded manifest for this session, or None if absent/corrupt."""
    path = _manifest_path(folder, session)
    if not path.is_file():
        return None
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return state if isinstance(state, dict) else None


def interrupted_publication(folder: Path, session: int) -> bool:
    """True if a batch for this session crashed before ``finalize_publication``."""
    state = publication_state(folder, session)
    return state is not None and state.get("status") == "in_progress"


@dataclass
class ReportPublication:
    created: dict[str, Path] = field(default_factory=dict)
    failed: dict[str, str] = field(default_factory=dict)

    @property
    def complete(self) -> bool:
        return bool(self.created) and not self.failed


def publish_reports(
    data: dict, folder: Path, targets: dict[str, Path], *,
    formats: tuple[str, ...] = ("html", "pdf"),
    html_export=None, pdf_export=None, machine_export=None,
) -> ReportPublication:
    """Use a single supplied snapshot and return success/failure per format."""
    if not data.get("history") or not data.get("summary"):
        raise ValueError("A completed saved assessment is required")
    allowed = {"html", "pdf", "json", "sarif"}
    if not formats or any(fmt not in allowed for fmt in formats):
        raise ValueError("Unsupported report formats")
    if len(set(formats)) != len(formats):
        raise ValueError("Duplicate report format")
    if html_export is None or pdf_export is None or machine_export is None:
        from penx_app.reporting.export import export_html, export_pdf
        from penx_app.reporting.machine_reports import write_machine_report
        html_export = html_export or export_html
        pdf_export = pdf_export or export_pdf
        machine_export = machine_export or write_machine_report

    folder.mkdir(parents=True, exist_ok=True)
    session = int(data["history"][0])
    begin_publication(folder, session, formats)
    result = ReportPublication()
    for fmt in formats:
        try:
            if fmt in {"json", "sarif"}:
                result.created[fmt] = Path(machine_export(data, folder, fmt=fmt))
                continue
            destination = targets[fmt]
            if destination.parent != folder:
                raise ValueError("Report path outside output directory")
            if destination.is_symlink():
                raise OSError("Refusing to overwrite symlink")
            if destination.exists() and not destination.is_file():
                raise OSError("Report destination is not a regular file")
            with tempfile.TemporaryDirectory(prefix=".penx-format-", dir=str(folder)) as temporary:
                renderer = html_export if fmt == "html" else pdf_export
                staged = Path(renderer(data, temporary))
                if not staged.is_file() or staged.parent.resolve() != Path(temporary).resolve():
                    raise OSError("Renderer did not create local report")
                if destination.is_symlink():
                    raise OSError("Refusing to overwrite symlink")
                os.replace(staged, destination)
            result.created[fmt] = destination
        except Exception as exc:
            result.failed[fmt] = f"{type(exc).__name__}: {exc}"
    finalize_publication(folder, session, result.created, result.failed)
    return result
