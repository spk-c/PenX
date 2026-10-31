"""Bounded local NVD cache keyed by CPE, never by API key.

Enabled by default; set PENX_NVD_DISK_CACHE=0 to opt out. The cache holds
upstream public vulnerability records, not scan logs, domains, authorization
credentials, or model responses. An expired entry is NOT used to assert
current vulnerability status while offline.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from pathlib import Path
import tempfile
import time

from penx_app.app_paths import APP_ROOT

CACHE_DIR = APP_ROOT / "data" / "nvd_cache"
TTL_SECONDS = 24 * 3600
MAX_CACHE_SIZE = 4 * 1024 * 1024
MAX_RECORDS = 100
# Bound the entire directory, not just the size of individual cached CPEs.
MAX_CACHE_FILES = 128
MAX_TOTAL_CACHE_BYTES = 64 * 1024 * 1024
_CACHE_FILENAME = re.compile(r"[0-9a-f]{64}\.json\\Z", re.ASCII)


def _safe_unlink(path: Path, info: os.stat_result) -> bool:
    """Never remove changed entries or arbitrary/symlinked user files."""
    try:
        current = path.lstat()
        if (not stat.S_ISREG(current.st_mode)
                or (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino)):
            return False
        path.unlink()
        return True
    except OSError:
        return False


def prune(*, now: float | None = None) -> None:
    """Best-effort TTL and LRU-like age pruning after a cache write.

    Only regular SHA-256-named cache entries are managed. A concurrently
    replaced entry is never deleted based on stale metadata. Filesystem mtime
    is used rather than opening/parsing every (potentially corrupt) JSON file.
    """
    try:
        if CACHE_DIR.is_symlink():
            return
        current_time = time.time() if now is None else now
        entries: list[tuple[float, Path, os.stat_result]] = []
        with os.scandir(CACHE_DIR) as listing:
            for candidate in listing:
                if not _CACHE_FILENAME.fullmatch(candidate.name):
                    continue
                try:
                    info = candidate.stat(follow_symlinks=False)
                except OSError:
                    continue
                if not stat.S_ISREG(info.st_mode):
                    continue
                path = CACHE_DIR / candidate.name
                if (info.st_size > MAX_CACHE_SIZE
                        or (0 <= current_time - info.st_mtime > TTL_SECONDS)):
                    _safe_unlink(path, info)
                    continue
                entries.append((info.st_mtime, path, info))
        entries.sort(key=lambda item: (item[0], item[1].name))
        count = len(entries)
        total = sum(info.st_size for _, _, info in entries)
        for _, path, info in entries:
            if count <= MAX_CACHE_FILES and total <= MAX_TOTAL_CACHE_BYTES:
                break
            if _safe_unlink(path, info):
                count -= 1
                total -= info.st_size
    except OSError:
        # Cache cleanup is optional: source research must still work offline.
        return



def enabled() -> bool:
    return os.getenv("PENX_NVD_DISK_CACHE", "1").lower() in ("1", "true", "yes")


def cache_path(cpe: str) -> Path:
    digest = hashlib.sha256(cpe.encode("utf-8")).hexdigest()
    return CACHE_DIR / (digest + ".json")


def load(cpe: str, *, now: float | None = None) -> tuple[dict, ...] | None:
    """Return unexpired public NVD records; malformed/expired caches are ignored."""
    if not enabled() or not isinstance(cpe, str) or not cpe.startswith("cpe:"):
        return None
    path = cache_path(cpe)
    try:
        # Open one file descriptor and bound the *actual* bytes consumed.
        # stat(path) followed by read_text(path) allowed a replaced/grown
        # file to bypass the original size/symlink check.
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0)
                     | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as stream:
            current_file = os.fstat(stream.fileno())
            path_file = path.lstat()
            if (not stat.S_ISREG(current_file.st_mode)
                    or not stat.S_ISREG(path_file.st_mode)
                    or (current_file.st_dev, current_file.st_ino)
                    != (path_file.st_dev, path_file.st_ino)
                    or current_file.st_size > MAX_CACHE_SIZE):
                return None
            payload = stream.read(MAX_CACHE_SIZE + 1)
        if len(payload) > MAX_CACHE_SIZE:
            return None
        entry = json.loads(payload.decode("utf-8"))
        if not isinstance(entry, dict) or entry.get("version") != 1:
            return None
        if entry.get("key") != hashlib.sha256(cpe.encode("utf-8")).hexdigest():
            return None
        fetched = entry.get("fetched_at")
        current = time.time() if now is None else now
        if (not isinstance(fetched, (float, int)) or isinstance(fetched, bool)
                or not 0 <= current - fetched <= TTL_SECONDS):
            return None
        items = entry.get("records")
        if not isinstance(items, list) or len(items) > MAX_RECORDS:
            return None
        if not all(isinstance(item, dict) for item in items):
            return None
        return tuple(items)
    except (OSError, UnicodeError, ValueError, TypeError):
        return None


def store(cpe: str, records: tuple[dict, ...], *, now: float | None = None) -> bool:
    """Atomically persist only bounded, successful catalogue responses."""
    if not enabled() or not isinstance(cpe, str) or not cpe.startswith("cpe:"):
        return False
    if (not isinstance(records, (tuple, list)) or len(records) > MAX_RECORDS
            or not all(isinstance(v, dict) for v in records)):
        return False
    data = {
        "version": 1,
        "key": hashlib.sha256(cpe.encode("utf-8")).hexdigest(),
        "fetched_at": time.time() if now is None else now,
        "records": records,
    }
    try:
        encoded = json.dumps(data, ensure_ascii=True, allow_nan=False,
                             separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError, OverflowError):
        # Cache failure is best-effort and must not abort CVE discovery.
        return False
    if len(encoded) > MAX_CACHE_SIZE:
        return False
    temp = None
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        if CACHE_DIR.is_symlink():
            return False
        path = cache_path(cpe)
        if path.is_symlink():
            return False
        with tempfile.NamedTemporaryFile(mode="wb", dir=CACHE_DIR, prefix=".nvd-",
                                         suffix=".tmp", delete=False) as handle:
            temp = Path(handle.name)
            handle.write(encoded)
        os.replace(temp, path)
        prune()
        return True
    except OSError:
        return False
    finally:
        if temp is not None:
            try:
                temp.unlink(missing_ok=True)
            except OSError:
                pass
