"""Opt-in faithful stdout bytes, not composite scanner presentation text."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat

from penx_app.domain.raw_artifact import MAX_ARTIFACT_BYTES
from penx_app.domain.stdout_bytes import StdoutByteCapture
from penx_app.file_output import publish_unique


def retain_stdout_bytes(raw: bytes, directory: str | Path,
                        *, decoded_text: str) -> StdoutByteCapture:
    """Write exact stdout bytes atomically; no silent lossy fallback."""
    if (not isinstance(raw, bytes) or not raw
            or len(raw) > MAX_ARTIFACT_BYTES):
        raise ValueError("Invalid or oversized stdout byte capture")
    if not isinstance(decoded_text, str):
        raise ValueError("Missing decoded stdout")
    # An exact, strict UTF-8 mapping of the actual runner presentation text
    # must exist; mixed stderr and invalid-UTF-8 captures cannot get a proof.
    if raw.decode("utf-8").strip() != decoded_text:
        raise ValueError("Stdout cannot establish displayed text equivalence")
    digest = hashlib.sha256(raw).hexdigest()
    path = publish_unique(directory, digest, ".bin", raw)
    return StdoutByteCapture(
        sha256=digest, size_bytes=len(raw), filename=path.name,
        text_sha256=hashlib.sha256(decoded_text.encode("utf-8")).hexdigest())


def verify_stdout_capture(ref: StdoutByteCapture, directory: str | Path,
                          *, text: str) -> bytes:
    """Read one capture without following linked paths; recheck both hashes."""
    if not isinstance(ref, StdoutByteCapture):
        raise ValueError("Invalid stdout capture reference")
    if not isinstance(text, str):
        raise ValueError("Original decoded output text must be supplied")
    root = Path(directory).resolve()
    path = root / ref.filename
    if path.is_symlink() or path.resolve().parent != root:
        raise ValueError("Unsafe stdout capture path")
    if path.exists() and not path.is_file():
        raise ValueError("Stdout capture must be a regular file")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0)
                 | getattr(os, "O_NOFOLLOW", 0)
                 | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as handle:
        opened = os.fstat(handle.fileno())
        named = path.lstat()
        if (not stat.S_ISREG(opened.st_mode)
                or not stat.S_ISREG(named.st_mode)
                or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)):
            raise ValueError("Stdout capture is not an unchanged regular file")
        if opened.st_size > MAX_ARTIFACT_BYTES:
            raise ValueError("Stdout capture exceeds size cap")
        raw = handle.read(MAX_ARTIFACT_BYTES + 1)
    if (len(raw) != ref.size_bytes
            or hashlib.sha256(raw).hexdigest() != ref.sha256):
        raise ValueError("Stdout byte hash/size mismatch")
    try:
        reproduced = raw.decode("utf-8").strip()
    except UnicodeDecodeError as exc:
        raise ValueError("Stdout capture was not valid UTF-8") from exc
    if (hashlib.sha256(text.encode("utf-8")).hexdigest() != ref.text_sha256
            or reproduced != text):
        raise ValueError("Stdout decoded text does not match capture")
    return raw
