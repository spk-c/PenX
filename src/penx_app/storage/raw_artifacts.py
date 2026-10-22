"""Opt-in bounded raw capture storage; hashes attest integrity, not authenticity."""
from __future__ import annotations

from dataclasses import replace
import hashlib
import os
from pathlib import Path
import stat

from penx_app.domain.raw_artifact import MAX_ARTIFACT_BYTES, RawArtifact
from penx_app.domain.scan_models import ScanResult, ScannerResult
from penx_app.file_output import publish_unique


def retain_artifacts(result: ScanResult, directory: str | Path) -> ScanResult:
    """Retain eligible trusted adapter text, preserving other metadata.

    Oversized captures are omitted, never silently truncated and hashed as if
    complete. At most 100 adapters / 100 MiB per call. No retention by default.
    """
    if len(result.results) > 100:
        raise ValueError("Too many raw artifacts")
    rows = []
    for row in result.results:
        if not row.text or not row.evidence or row.status == "FAILED":
            rows.append(row)
            continue
        # Bound allocation before encoding multi-byte text.
        if len(row.text) > MAX_ARTIFACT_BYTES:
            rows.append(replace(row, raw_artifact=None))
            continue
        encoded = row.text.encode("utf-8")
        if len(encoded) > MAX_ARTIFACT_BYTES:
            rows.append(replace(row, raw_artifact=None))
            continue
        digest = hashlib.sha256(encoded).hexdigest()
        existing = RawArtifact(digest, len(encoded), digest + '.txt')
        try:
            validate_artifact(replace(row, raw_artifact=existing), directory)
        except (OSError, ValueError):
            pass
        else:
            rows.append(replace(row, raw_artifact=existing))
            continue
        # Preserve adapter line endings on Windows as well as Linux.
        path = publish_unique(directory, digest, ".txt", row.text, newline="")
        rows.append(replace(row, raw_artifact=RawArtifact(digest, len(encoded), path.name)))
    return replace(result, results=tuple(rows))


def validate_artifact(adapter: ScannerResult, directory: str | Path) -> ScannerResult:
    """Load, hash and anchor-check a capture using a trusted metadata reference.

    The caller chooses the artifact directory; metadata cannot supply a path.
    Missing, changed, oversized or linked files fail closed. This does not
    establish vulnerability applicability or authenticate an untrusted import.
    """
    ref = adapter.raw_artifact
    if ref is None:
        raise ValueError("No raw artifact reference")
    root = Path(directory).resolve()
    path = root / ref.filename
    if path.is_symlink() or path.resolve().parent != root:
        raise ValueError("Unsafe raw artifact path")
    if path.exists() and not path.is_file():
        raise ValueError("Raw artifact must be a regular file")
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_BINARY', 0)
                 | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    with os.fdopen(fd, 'rb') as handle:
        opened = os.fstat(handle.fileno())
        named = path.lstat()
        if (not stat.S_ISREG(opened.st_mode) or not stat.S_ISREG(named.st_mode)
                or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)):
            raise ValueError('Raw artifact must be an unchanged regular file')
        if opened.st_size > MAX_ARTIFACT_BYTES:
            raise ValueError('Raw artifact integrity check failed')
        content = handle.read(MAX_ARTIFACT_BYTES + 1)
    if len(content) != ref.size_bytes or hashlib.sha256(content).hexdigest() != ref.sha256:
        raise ValueError("Raw artifact integrity check failed")
    restored = replace(adapter, text=content.decode("utf-8"))
    if any(not record.matches(restored) for record in adapter.evidence_records):
        raise ValueError("Raw artifact evidence anchors do not match")
    return restored
