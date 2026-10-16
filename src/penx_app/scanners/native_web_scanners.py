"""Bounded Windows-native web scanner argument builders and JSONL summaries.

No shell, no caller-supplied flags, no auto-downloads, no user-supplied arbitrary
URLs inside template/wordlist arguments. These helpers never run commands.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
from urllib.parse import urlsplit

from penx_app.app_paths import APP_ROOT

DEFAULT_FFUF_PATHS = (
    "robots.txt", "sitemap.xml", ".well-known/security.txt", "admin",
    "login", "wp-login.php", "wp-admin", "api", "health", "status",
    "backup", "config", "assets", "static", "docs", "README",
)
_ALLOWED_PATH = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,100}\Z")
_NAMES = {"nuclei", "httpx", "ffuf", "subfinder", "katana"}


def find_native(name: str) -> str | None:
    """Prefer configured portable binaries over PATH (especially httpx name collisions)."""
    if name not in _NAMES:
        raise ValueError("Unsupported native scanner")
    override = os.getenv(f"PENX_{name.upper()}_PATH", "").strip().strip('"')
    if override:
        path = Path(override)
        return str(path) if path.is_file() else None
    suffix = ".exe" if os.name == "nt" else ""
    for place in (APP_ROOT / "vendor" / "bin" / (name + suffix),
                  APP_ROOT / "bin" / (name + suffix)):
        if place.is_file():
            return str(place)
    candidate = shutil.which(name)
    if candidate and name == "httpx":
        # The Python HTTPX package installs a different command with this name.
        # Accept PATH entries only after identifying ProjectDiscovery's CLI.
        try:
            check = subprocess.run([candidate, "-version"], shell=False,
                                   capture_output=True, text=True, timeout=5, check=False)
            signature = (check.stdout or "") + "\n" + (check.stderr or "")
            if check.returncode or not re.search(
                r"(?i)(?:projectdiscovery|current version:\s*v?\d|httpx version:\s*v?\d)", signature
            ):
                return None
        except (OSError, subprocess.TimeoutExpired):
            return None
    return candidate


def web_endpoint(value: str, validate_web_target) -> str:
    """Single root endpoint, preserving an explicitly authorized scheme and port."""
    value = validate_web_target(value)
    url = value if "://" in value else "https://" + value
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Only http(s) web origins are supported")
    if parsed.username or parsed.password or parsed.fragment or parsed.query:
        raise ValueError("Web scanner target cannot contain credentials, fragment or query")
    if parsed.path not in ("", "/"):
        raise ValueError("Use a web origin, without a custom path, for this scan")
    # validate_web_target already checks numeric port bounds and host syntax.
    return f"{parsed.scheme}://{parsed.netloc}"


def template_install_directory() -> Path:
    """The same custom template location is used by setup and scan preflights."""
    override = os.getenv("PENX_NUCLEI_TEMPLATES", "").strip().strip('"')
    return Path(override).expanduser() if override else APP_ROOT / "vendor" / "nuclei-templates"


def has_nuclei_templates(directory: Path, *, allow_incomplete: bool = False) -> bool:
    """A directory or a timed-out partial download is not a valid installation."""
    if not directory.is_dir():
        return False
    if not allow_incomplete and (directory / ".penx-template-update-incomplete").exists():
        return False
    try:
        return (next(directory.rglob("*.yaml"), None) is not None
                or next(directory.rglob("*.yml"), None) is not None)
    except OSError:
        return False


def nuclei_templates() -> Path | None:
    """Require actual local YAML templates without downloads during scans."""
    selected = template_install_directory()
    choices = ([selected] if os.getenv("PENX_NUCLEI_TEMPLATES", "").strip()
               else [selected, Path.home() / "nuclei-templates"])
    return next((folder for folder in choices if has_nuclei_templates(folder)), None)


def nuclei_args(executable: str, origin: str, templates: Path | None = None) -> list[str]:
    args = [executable, "-u", origin, "-jsonl", "-silent", "-no-color",
            "-or", "-ni", "-duc", "-pt", "http,ssl", "-severity",
            "low,medium,high,critical", "-etags", "dos,fuzz,bruteforce",
            "-rl", "2", "-c", "1", "-bs", "1", "-timeout", "5",
            "-retries", "0"]
    if templates is not None:
        args.extend(["-t", str(templates)])
    return args


def httpx_args(executable: str, origin: str) -> list[str]:
    return [executable, "-u", origin, "-j", "-silent", "-duc",
            "-status-code", "-title", "-tech-detect", "-server",
            "-rl", "3", "-t", "1", "-timeout", "7", "-retries", "0"]


def subfinder_args(executable: str, domain: str) -> list[str]:
    """Passive host discovery only; never ask Subfinder to resolve or probe."""
    return [executable, "-d", domain, "-silent", "-json", "-max-time", "2"]


def katana_args(executable: str, origin: str) -> list[str]:
    """Constrain crawler to exact FQDN, root depth and request rate."""
    return [executable, "-u", origin, "-jsonl", "-silent", "-d", "1",
            "-fs", "fqdn", "-c", "1", "-rl", "2", "-timeout", "5"]


def ffuf_args(executable: str, origin: str, wordlist: Path) -> list[str]:
    return [executable, "-u", origin.rstrip("/") + "/FUZZ", "-w", str(wordlist),
            "-json", "-s", "-noninteractive", "-rate", "2", "-t", "1",
            "-timeout", "5", "-maxtime", "50", "-mc",
            "200,204,301,302,307,308,401,403,405", "-X", "GET"]


def ffuf_words() -> list[str]:
    """Only simple relative single-segment paths, bounded to 80 requests."""
    override = os.getenv("PENX_FFUF_WORDLIST", "").strip().strip('"')
    if not override:
        return list(DEFAULT_FFUF_PATHS)
    path = Path(override)
    if not path.is_file() or path.stat().st_size > 8192:
        raise ValueError("ffuf wordlist missing or larger than 8 KiB")
    words: list[str] = []
    seen: set[str] = set()
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        word = line.strip()
        if not word or word.startswith("#"):
            continue
        if not _ALLOWED_PATH.fullmatch(word) or word in (".", "..") or ".." in word:
            raise ValueError("Unsafe ffuf wordlist entry; use single relative path names")
        if word in seen:
            continue  # Only distinct entries increase the number of requests.
        if len(words) >= 80:
            raise ValueError("ffuf wordlist exceeds 80 unique entries")
        seen.add(word)
        words.append(word)
    if not words:
        raise ValueError("ffuf wordlist is empty")
    return words


def _single_line(value, limit: int = 200) -> str:
    """Prevent response-controlled newlines/ANSI from forging scanner records."""
    text = str(value or "")
    text = re.sub(r"[\x00-\x1f\x7f\u2028\u2029]+", " ", text)
    return text[:limit]


def summarize_output(scanner: str, raw: str, *, max_items: int = 60) -> tuple[str, bool]:
    """Remove huge raw HTTP bodies and never treat empty results as vulnerabilities."""
    output = []
    capped = False
    for line in str(raw).splitlines():
        if len(line) > 1_000_000:
            continue
        try:
            item = json.loads(line)
        except (ValueError, TypeError):
            continue
        if not isinstance(item, dict):
            continue
        if scanner == "nuclei":
            info = item.get("info") or {}
            if not isinstance(info, dict):
                info = {}
            template = _single_line(item.get("template-id"), 120)
            if not template:
                continue
            severity = _single_line(info.get("severity") or "unknown", 20)
            name = _single_line(info.get("name"), 150)
            matched = _single_line(item.get("matched-at") or item.get("host"), 200)
            output.append(f"TEMPLATE {template} | {severity} | {name} | {matched}")
        elif scanner == "httpx":
            url = _single_line(item.get("url") or item.get("input"), 200)
            if not url:
                continue
            code = _single_line(item.get("status_code"), 8)
            server = _single_line(item.get("webserver"), 80)
            title = _single_line(item.get("title"), 150)
            tech = item.get("tech") or []
            if not isinstance(tech, list):
                tech = []
            output.append(f"HTTP {code} | {url} | {server} | {title} | technologies: {', '.join(_single_line(t, 60) for t in tech[:12])[:250]}")
        elif scanner == "ffuf":
            url = _single_line(item.get("url"), 220)
            if not url:
                continue
            code = _single_line(item.get("status"), 8)
            output.append(f"ENDPOINT HTTP {code} | {url}")
        if len(output) > max_items:
            # A single additional *valid* row proves actual truncation.
            output.pop()
            capped = True
            break
    if output:
        return "\n".join(output) + ("\n[Results capped for display]" if capped else ""), True
    return {
        "nuclei": "Nuclei returned no template matches. This is not proof that the target is free from vulnerabilities; check coverage and HTTP availability.",
        "httpx": "httpx returned no reachable HTTP endpoint or parseable JSON result.",
        "ffuf": "ffuf finished without matching paths.",
    }[scanner], False
