"""Safe, exclusive publication of completed text and atomic config replacement."""
from __future__ import annotations
import os
import tempfile
from pathlib import Path


def _stage(root: Path, text: str, *, newline: str | None = None) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    pending = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", dir=root, prefix=".penx-stage-", suffix=".tmp",
            encoding="utf-8", delete=False, newline=newline,
        ) as handle:
            pending = Path(handle.name)
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        return pending
    except BaseException:
        if pending is not None:
            pending.unlink(missing_ok=True)
        raise


def publish_unique(directory: str | Path, stem: str, suffix: str, text: str,
                   *, newline: str | None = None) -> Path:
    """Atomic exclusive publication: existing files and links are never overwritten."""
    root = Path(directory)
    staged = _stage(root, text, newline=newline)
    try:
        for index in range(101):
            path = root / f"{stem}{('_' + str(index)) if index else ''}{suffix}"
            try:
                os.link(staged, path)
                return path
            except FileExistsError:
                continue
        raise FileExistsError("Too many existing PenX exports")
    finally:
        staged.unlink(missing_ok=True)


def replace_config(path: str | Path, text: str) -> None:
    """Stage complete configuration content with unique filenames and replace."""
    dest = Path(path)
    if dest.is_symlink() or (dest.exists() and not dest.is_file()):
        raise OSError("Refusing unsafe configuration destination")
    staged = _stage(dest.parent, text)
    try:
        if dest.is_symlink() or (dest.exists() and not dest.is_file()):
            raise OSError("Refusing unsafe configuration destination")
        os.replace(staged, dest)
    finally:
        staged.unlink(missing_ok=True)
