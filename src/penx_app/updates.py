"""Conservative GitLab release updater for installed PenX on Windows.

Release checks only read public metadata. Installing requires explicit user
approval, validates official GitLab release asset URLs, verifies the SHA-256
checksum, and starts the interactive Inno Setup installer. Portable users only
receive notices; no scanner or release binary is installed automatically.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from penx_app.app_paths import APP_ROOT, installed_mode
from penx_app.version import VERSION

PROJECT = "SLP-DEV1/PenX"
PROJECT_ID = 87731916
PROJECT_URL = "https://gitlab.com/" + PROJECT
API = f"https://gitlab.com/api/v4/projects/{PROJECT_ID}/releases?per_page=100"
DOWNLOAD_PREFIX = PROJECT_URL + "/-/releases/"
INSTALLER_NAME = "PenX-Setup-x64.exe"
CHECKSUM_NAME = "SHA256SUMS.txt"
MAX_INSTALLER_BYTES = 250 * 1024 * 1024
VERSION_RE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")
CHECK_INTERVAL = 24 * 60 * 60
# GitLab may redirect project-owned artifacts to its Google Cloud object storage.
DOWNLOAD_HOSTS = frozenset({"gitlab.com", "storage.googleapis.com"})


@dataclass(frozen=True)
class Release:
    tag: str
    installer_url: str
    checksums_url: str
    page_url: str


def version_tuple(value: str) -> tuple[int, int, int]:
    match = VERSION_RE.fullmatch(value if value.startswith("v") else "v" + value)
    if not match:
        raise ValueError("Unsupported release version")
    return tuple(int(part) for part in match.groups())


def _asset_url(tag: str, asset: str) -> str:
    version_tuple(tag)
    if asset not in (INSTALLER_NAME, CHECKSUM_NAME):
        raise ValueError("Unsupported release asset")
    return f"{DOWNLOAD_PREFIX}{tag}/downloads/{asset}"


def _safe_url(url: str, *, asset: str, tag: str) -> bool:
    return url == _asset_url(tag, asset)


def _read_url(url: str, *, limit: int = 262144) -> bytes:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname != "gitlab.com":
        raise ValueError("Unexpected release metadata host")
    req = Request(url, headers={"User-Agent": f"PenX/{VERSION}", "Accept": "application/json"})
    with urlopen(req, timeout=8) as response:
        final = urlsplit(response.geturl())
        if final.scheme != "https" or final.hostname not in DOWNLOAD_HOSTS:
            raise ValueError("Unexpected release response host")
        data = response.read(limit + 1)
        if len(data) > limit:
            raise ValueError("Update response is too large")
        return data


def fetch_latest() -> Release:
    payload = json.loads(_read_url(API))
    if not isinstance(payload, list):
        raise ValueError("Invalid GitLab Releases response")
    candidates = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        tag = item.get("tag_name", "")
        if not isinstance(tag, str) or not VERSION_RE.fullmatch(tag):
            continue
        if item.get("upcoming_release"):
            continue
        when = item.get("released_at")
        if isinstance(when, str):
            try:
                if datetime.fromisoformat(when.replace("Z", "+00:00")) > datetime.now(timezone.utc):
                    continue
            except ValueError:
                continue
        candidates.append((version_tuple(tag), item))
    if not candidates:
        raise ValueError("No stable GitLab release found")
    _, release = max(candidates, key=lambda value: value[0])
    tag = release["tag_name"]
    assets = release.get("assets")
    links = assets.get("links", []) if isinstance(assets, dict) else []
    if not isinstance(links, list):
        raise ValueError("Invalid GitLab release asset links")
    urls = {}
    for link in links:
        if not isinstance(link, dict):
            continue
        name, url = link.get("name"), link.get("direct_asset_url")
        if name in (INSTALLER_NAME, CHECKSUM_NAME) and isinstance(url, str):
            if _safe_url(url, asset=name, tag=tag):
                urls[name] = url
    installer = urls.get(INSTALLER_NAME, "")
    checksums = urls.get(CHECKSUM_NAME, "")
    # Never offer an installer without the matching trusted checksum.
    if installer and not checksums:
        raise ValueError("Official GitLab release checksum asset missing")
    return Release(tag, installer, checksums, f"{PROJECT_URL}/-/releases/{tag}")


def is_newer(release: Release) -> bool:
    return version_tuple(release.tag) > version_tuple(VERSION)


def _expected_hash(text: str) -> str:
    matches = []
    for line in text.splitlines():
        match = re.fullmatch(r"([a-fA-F0-9]{64})\s+\*?PenX-Setup-x64\.exe", line.strip())
        if match:
            matches.append(match.group(1).lower())
    if len(matches) != 1:
        raise ValueError("Installer SHA-256 is missing or ambiguous")
    return matches[0]


def download_verified_installer(release: Release, *, root: Path = APP_ROOT) -> Path:
    if not is_newer(release) or not release.installer_url:
        raise ValueError("No eligible installer update")
    if not _safe_url(release.installer_url, asset=INSTALLER_NAME, tag=release.tag):
        raise ValueError("Untrusted installer URL")
    if not _safe_url(release.checksums_url, asset=CHECKSUM_NAME, tag=release.tag):
        raise ValueError("Untrusted checksum URL")
    expected = _expected_hash(_read_url(release.checksums_url, limit=65536).decode("ascii"))
    update_dir = root / "updates"
    update_dir.mkdir(parents=True, exist_ok=True)
    fd, filename = tempfile.mkstemp(prefix="penx-update-", suffix=".exe", dir=update_dir)
    target = Path(filename)
    try:
        digest = hashlib.sha256()
        total = 0
        req = Request(release.installer_url, headers={"User-Agent": f"PenX/{VERSION}"})
        with os.fdopen(fd, "wb") as out, urlopen(req, timeout=30) as response:
            final = urlsplit(response.geturl())
            if final.scheme != "https" or final.hostname not in DOWNLOAD_HOSTS:
                raise ValueError("Unexpected installer download host")
            while chunk := response.read(1024 * 1024):
                total += len(chunk)
                if total > MAX_INSTALLER_BYTES:
                    raise ValueError("Installer exceeds size limit")
                digest.update(chunk)
                out.write(chunk)
        if not total or digest.hexdigest() != expected:
            raise ValueError("Installer SHA-256 verification failed")
        return target
    except BaseException:
        target.unlink(missing_ok=True)
        raise


def check_update(*, quiet: bool = False) -> Release | None:
    try:
        latest = fetch_latest()
    except (OSError, ValueError, TimeoutError, json.JSONDecodeError) as exc:
        if not quiet:
            print(f"[WARN] Could not check GitLab Releases: {exc}")
        return None
    if not quiet:
        print(f"Installed PenX version: v{VERSION}")
        print(f"Latest stable GitLab release: {latest.tag}")
        if is_newer(latest):
            print(f"New release available: {latest.page_url}")
            if not latest.installer_url:
                print("This release has no verified Windows installer; download it manually.")
        else:
            print("[OK] PenX is up to date.")
    return latest if is_newer(latest) else None


def update_interactive() -> bool:
    """Only an explicit positive answer can start the installer."""
    latest = check_update()
    if latest is None:
        return False
    if os.name != "nt" or not installed_mode() or not latest.installer_url:
        print(f"Open {latest.page_url} for the available download.")
        print("Automatic installation is only supported for verified installed Windows editions.")
        return False
    try:
        answer = input(f"Download, verify and install {latest.tag}? [y/N]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    if answer not in ("y", "yes", "j", "ja"):
        return False
    try:
        installer = download_verified_installer(latest)
        print("[OK] Installer checksum verified. Starting interactive setup...")
        subprocess.Popen([str(installer)], shell=False, cwd=str(installer.parent))
        return True
    except (OSError, ValueError, TimeoutError) as exc:
        print(f"[ERROR] Update aborted: {exc}")
        return False


def startup_notice() -> None:
    """Read-only, once-per-day notice for installed copies."""
    if not installed_mode() or os.environ.get("PENX_AUTO_UPDATE_CHECK", "on").lower() in (
        "off", "0", "false", "no"
    ):
        return
    marker = APP_ROOT / "data" / ".last-update-check"
    try:
        if marker.is_file() and time.time() - float(marker.read_text().strip()) < CHECK_INTERVAL:
            return
    except (ValueError, OSError):
        pass
    try:
        latest = fetch_latest()
    except (OSError, ValueError, TimeoutError, json.JSONDecodeError):
        return
    try:
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text(str(time.time()), encoding="ascii")
    except OSError:
        pass
    if is_newer(latest):
        print(f"[UPDATE] PenX {latest.tag} is available: {latest.page_url}")
        print("Use menu [13] to review the update. Nothing is installed automatically.")
