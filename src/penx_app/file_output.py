"""Safe, exclusive publication of completed text and atomic config replacement."""
from __future__ import annotations
import os
import tempfile
import uuid
from pathlib import Path


def _stage(root: Path, text: str | bytes, *, newline: str | None = None) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    pending = None
    try:
        with tempfile.NamedTemporaryFile(
            "wb" if isinstance(text, bytes) else "w", dir=root, prefix=".penx-stage-", suffix=".tmp",
            encoding=None if isinstance(text, bytes) else "utf-8", delete=False,
            newline=None if isinstance(text, bytes) else newline,
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


def publish_unique(directory: str | Path, stem: str, suffix: str, text: str | bytes,
                   *, newline: str | None = None) -> Path:
    """Atomic exclusive publication: existing files and links are never overwritten."""
    if (not isinstance(stem, str) or not stem or stem in ('.', '..')
            or not isinstance(suffix, str)
            or any(char in stem + suffix for char in ('/', '\\', ':', '\0'))):
        raise ValueError('Export filename must be a single safe path component')
    root = Path(directory)
    staged = _stage(root, text, newline=newline)
    try:
        for index in range(109):
            tail = ('_' + str(index)) if index else ''
            if index > 100:
                tail = '_' + uuid.uuid4().hex
            path = root / f"{stem}{tail}{suffix}"
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
