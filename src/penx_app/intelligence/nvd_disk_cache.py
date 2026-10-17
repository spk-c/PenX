"""Opt-in, bounded local NVD cache keyed by CPE, never by API key.

The cache holds upstream public vulnerability records, not scan logs, domains,
authorization credentials, or model responses. An expired entry is NOT used to
assert current vulnerability status while offline.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
import time

from penx_app.app_paths import APP_ROOT

CACHE_DIR = APP_ROOT / "data" / "nvd_cache"
TTL_SECONDS = 24 * 3600
MAX_CACHE_SIZE = 4 * 1024 * 1024
MAX_RECORDS = 100


def enabled() -> bool:
    return os.getenv("PENX_NVD_DISK_CACHE", "0").lower() in ("1", "true", "yes")


def cache_path(cpe: str) -> Path:
    digest = hashlib.sha256(cpe.encode("utf-8")).hexdigest()
    return CACHE_DIR / (digest + ".json")


def load(cpe: str, *, now: float | None = None) -> tuple[dict, ...] | None:
    """Return unexpired public NVD records; malformed/expired caches are ignored."""
    if not enabled() or not isinstance(cpe, str) or not cpe.startswith("cpe:"):
        return None
    path = cache_path(cpe)
    try:
        if path.is_symlink() or path.stat().st_size > MAX_CACHE_SIZE:
            return None
        entry = json.loads(path.read_text(encoding="utf-8"))
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
    if len(records) > MAX_RECORDS or not all(isinstance(v, dict) for v in records):
        return False
    data = {
        "version": 1,
        "key": hashlib.sha256(cpe.encode("utf-8")).hexdigest(),
        "fetched_at": time.time() if now is None else now,
        "records": records,
    }
    encoded = json.dumps(data, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    if len(encoded) > MAX_CACHE_SIZE:
        return False
    temp = None
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        path = cache_path(cpe)
        if path.is_symlink():
            return False
        with tempfile.NamedTemporaryFile(mode="wb", dir=CACHE_DIR, prefix=".nvd-",
                                         suffix=".tmp", delete=False) as handle:
            temp = Path(handle.name)
            handle.write(encoded)
        os.replace(temp, path)
        return True
    except OSError:
        return False
    finally:
        if temp is not None:
            try:
                temp.unlink(missing_ok=True)
            except OSError:
                pass
