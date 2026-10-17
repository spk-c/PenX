"""Same-origin URL/parameter inventory for explicitly authorized web mapping.

Never stores query values, HTTP bodies, cookies or credentials. Inventory files
are bounded JSON and are not authorization to probe a different host.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from urllib.parse import unquote, unquote_plus, urlsplit

from penx_app.app_paths import application_root

MAX_ENDPOINTS = 150
MAX_PARAMETERS = 24
MAX_FILE_BYTES = 96_000
_SAFE_PARAM = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.\[\]-]{0,63}\Z", re.ASCII)
_BAD_ESCAPES = re.compile(r"%(?:00|0[0-9a-f]|1[0-9a-f]|2f|5c|7f)", re.IGNORECASE)


def _authority(url: str) -> tuple[str, str, int]:
    parsed = urlsplit(url)
    if (parsed.scheme not in ("http", "https") or not parsed.hostname
            or parsed.username is not None or parsed.password is not None):
        raise ValueError("Expected a credential-free HTTP(S) origin")
    port = parsed.port
    if port == 0 or parsed.netloc.endswith(":"):
        raise ValueError("Invalid port")
    return parsed.scheme, parsed.hostname.casefold(), port or (443 if parsed.scheme == "https" else 80)


def normalize_discovery(candidate: str, origin: str) -> tuple[str, tuple[str, ...]] | None:
    """Normalize only a URL on the *exact* authorized scheme/host/effective port."""
    if (not isinstance(candidate, str) or len(candidate) > 2048
            or any(ord(c) < 33 or ord(c) == 127 for c in candidate)
            or "\\" in candidate):
        return None
    try:
        if _authority(candidate) != _authority(origin):
            return None
        parsed = urlsplit(candidate)
        if _BAD_ESCAPES.search(parsed.path) or len(parsed.path) > 320:
            return None
        decoded = unquote(parsed.path)
        # Reject nested encodings that a downstream proxy might decode again.
        if re.search(r"%(?:2e|2f|5c|25|00)", decoded, re.IGNORECASE):
            return None
        if (any(ord(ch) < 32 or ord(ch) == 127 for ch in decoded)
                or "\\" in decoded or any(seg in (".", "..") for seg in decoded.split("/"))
                or "//" in decoded or not decoded.startswith("/") and decoded != ""):
            return None
        path = parsed.path or "/"
        # Only retain names; never persist secret-bearing query values.
        params: set[str] = set()
        if len(parsed.query) > 2048:
            return None
        for pair in parsed.query.split("&"):
            if not pair:
                continue
            key = unquote_plus(pair.split("=", 1)[0])
            if not _SAFE_PARAM.fullmatch(key):
                return None
            params.add(key)
            if len(params) > MAX_PARAMETERS:
                return None
        return origin.rstrip("/") + path, tuple(sorted(params))
    except (ValueError, UnicodeError):
        return None


@dataclass
class EndpointInventory:
    origin: str
    entries: dict[str, dict[str, set[str]]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _authority(self.origin)
        parsed = urlsplit(self.origin)
        if parsed.query or parsed.fragment or parsed.path not in ("", "/"):
            raise ValueError("Inventory requires a web origin, not a URL with path/query")
        # A canonical hostname avoids separate files for differently cased
        # spellings of the same authorized origin.
        raw_host = parsed.hostname
        if raw_host is None:
            raise ValueError("Inventory origin needs a hostname")
        host = raw_host.casefold()
        host_text = "[" + host + "]" if ":" in host else host
        port = ":" + str(parsed.port) if parsed.port is not None else ""
        self.origin = parsed.scheme + "://" + host_text + port

    def add(self, candidate: str, source: str) -> bool:
        if source not in ("katana", "ffuf"):
            raise ValueError("Unsupported inventory evidence source")
        normalized = normalize_discovery(candidate, self.origin)
        if normalized is None:
            return False
        url, params = normalized
        if url not in self.entries and len(self.entries) >= MAX_ENDPOINTS:
            return False
        item = self.entries.setdefault(url, {"parameters": set(), "sources": set()})
        item["parameters"].update(params)
        item["sources"].add(source)
        return True

    def collect_jsonl(self, raw: str, scanner: str) -> tuple[int, int]:
        """Accept typed scanner JSON lines only; ignore errors and malformed siblings."""
        if scanner not in ("katana", "ffuf"):
            raise ValueError("Unsupported inventory source")
        good = bad = 0
        for line in raw.splitlines()[:3000]:
            if len(line) > 8192:
                bad += 1
                continue
            try:
                obj = json.loads(line)
            except (ValueError, TypeError):
                bad += 1
                continue
            if not isinstance(obj, dict):
                bad += 1
                continue
            if scanner == "katana":
                req = obj.get("request")
                candidate = req.get("endpoint") if isinstance(req, dict) else None
                if obj.get("error"):
                    bad += 1
                    continue
            else:
                candidate = obj.get("url")
                # Only ffuf results with an explicit returned HTTP status.
                if not isinstance(obj.get("status"), int):
                    bad += 1
                    continue
            if isinstance(candidate, str) and self.add(candidate, scanner):
                good += 1
            else:
                bad += 1
        return good, bad

    def paths_for_fuzz(self, max_dirs: int = 3) -> list[str]:
        """Return safe discovered directory prefixes; never query-param fuzz."""
        dirs: set[str] = set()
        for url in self.entries:
            path = urlsplit(url).path
            segments = [p for p in path.split("/") if p]
            if not segments:
                continue
            # A directly discovered directory can be used; for a file-like
            # endpoint use its parent. All planned URLs remain same-origin.
            if path.endswith("/") and len(segments) <= 3:
                directory = "/" + "/".join(segments) + "/"
            elif len(segments) > 1 and len(segments) <= 4:
                directory = "/" + "/".join(segments[:-1]) + "/"
            else:
                continue
            if any(part.casefold() in ("logout", "signout", "delete", "remove",
                                       "purchase", "checkout", "reset", "transfer")
                   for part in directory.split("/")):
                continue
            if len(directory) < 150:
                dirs.add(self.origin + directory)
        return sorted(dirs)[:max(0, min(max_dirs, 8))]

    def public_json(self) -> dict:
        return {
            "schema": "penx-endpoint-inventory-v1",
            "origin": self.origin,
            "endpoints": [
                {"url": url, "parameters": sorted(data["parameters"]),
                 "sources": sorted(data["sources"])}
                for url, data in sorted(self.entries.items())
            ],
        }

    def summary(self, max_rows: int = 30) -> str:
        lines = ["[SAME-ORIGIN ENDPOINT INVENTORY: paths and parameter names only]"]
        for url, row in list(sorted(self.entries.items()))[:max_rows]:
            info = (" [parameters: " + ", ".join(sorted(row["parameters"])) + "]"
                    if row["parameters"] else "")
            lines.append(url + info)
        if len(self.entries) > max_rows:
            lines.append(f"[{len(self.entries) - max_rows} further endpoints retained in local inventory]")
        return "\n".join(lines)


def inventory_path(origin: str, *, directory: Path | None = None) -> Path:
    base = directory if directory is not None else application_root() / "data" / "endpoints"
    digest = hashlib.sha256(origin.encode("utf-8")).hexdigest()[:32]
    return base / (digest + ".json")


def load_inventory(origin: str, *, directory: Path | None = None) -> EndpointInventory:
    inv = EndpointInventory(origin)
    path = inventory_path(inv.origin, directory=directory)
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0)
                     | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as stream:
            opened = os.fstat(stream.fileno())
            named = path.lstat()
            if (not stat.S_ISREG(opened.st_mode) or not stat.S_ISREG(named.st_mode)
                    or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
                    or opened.st_size > MAX_FILE_BYTES):
                return inv
            data = stream.read(MAX_FILE_BYTES + 1)
        if len(data) > MAX_FILE_BYTES:
            return inv
        obj = json.loads(data)
        if (not isinstance(obj, dict) or obj.get("schema") != "penx-endpoint-inventory-v1"
                or obj.get("origin") != inv.origin
                or not isinstance(obj.get("endpoints"), list)):
            return inv
        for entry in obj["endpoints"][:MAX_ENDPOINTS]:
            if (not isinstance(entry, dict) or not isinstance(entry.get("url"), str)
                    or not isinstance(entry.get("parameters"), list)
                    or not isinstance(entry.get("sources"), list)):
                continue
            url = entry["url"]
            normalized = normalize_discovery(url, inv.origin)
            if normalized is None or normalized[0] != url:
                continue
            sources = [s for s in entry["sources"] if s in ("katana", "ffuf")]
            keys = [p for p in entry["parameters"]
                    if isinstance(p, str) and _SAFE_PARAM.fullmatch(p)]
            if len(keys) > MAX_PARAMETERS or not sources:
                continue
            inv.entries[url] = {"parameters": set(keys), "sources": set(sources)}
    except (OSError, ValueError, TypeError, UnicodeError):
        return inv
    return inv


def save_inventory(inv: EndpointInventory, *, directory: Path | None = None) -> Path:
    path = inventory_path(inv.origin, directory=directory)
    data = (json.dumps(inv.public_json(), ensure_ascii=True, separators=(",", ":"))
            + "\n").encode("utf-8")
    if len(data) > MAX_FILE_BYTES:
        raise ValueError("Endpoint inventory exceeds size limit")
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.parent.is_symlink():
        raise ValueError("Inventory directory cannot be a symlink")
    temp: str | None = None
    try:
        with tempfile.NamedTemporaryFile(mode="wb", dir=path.parent,
                                         prefix=".penx-endpoints-", suffix=".tmp",
                                         delete=False) as stream:
            temp = stream.name
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
    finally:
        if temp is not None:
            try:
                os.unlink(temp)
            except FileNotFoundError:
                pass
    return path
