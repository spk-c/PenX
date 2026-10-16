"""Conservative GitHub release updater for *installed* PenX on Windows.

Checking never downloads or executes software. Installing always requires the
user to explicitly agree, checks the release's SHA-256 and leaves rollback to
the interactive Inno Setup installer. Portable users only get release notices.
"""
from __future__ import annotations

from dataclasses import dataclass
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

API = "https://api.github.com/repos/SLP-DEV1/PenX/releases/latest"
DOWNLOAD_PREFIX = "https://github.com/SLP-DEV1/PenX/releases/download/"
INSTALLER_NAME = "PenX-Setup-x64.exe"
CHECKSUM_NAME = "SHA256SUMS.txt"
MAX_INSTALLER_BYTES = 250 * 1024 * 1024
VERSION_RE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")
CHECK_INTERVAL = 24 * 60 * 60


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


def _safe_url(url: str, *, asset: str, tag: str) -> bool:
    """Allow only the exact official release asset, never third-party URLs."""
    return url == f"{DOWNLOAD_PREFIX}{tag}/{asset}"


def _read_url(url: str, *, limit: int = 262144) -> bytes:
    req = Request(url, headers={"User-Agent": f"PenX/{VERSION}", "Accept": "application/vnd.github+json"})
    with urlopen(req, timeout=8) as response:
        # GitHub release downloads redirect to its own asset CDN.
        parsed = urlsplit(response.geturl())
        if parsed.scheme != "https" or parsed.hostname not in (
            "api.github.com", "github.com", "release-assets.githubusercontent.com",
        ):
            raise ValueError("Unexpected update download host")
        data = response.read(limit + 1)
        if len(data) > limit:
            raise ValueError("Update response is too large")
        return data


def fetch_latest() -> Release:
    payload = json.loads(_read_url(API))
    if not isinstance(payload, dict) or payload.get("draft") or payload.get("prerelease"):
        raise ValueError("No stable GitHub release found")
    tag = payload.get("tag_name", "")
    version_tuple(tag)
    assets = payload.get("assets", [])
    if not isinstance(assets, list):
        raise ValueError("Invalid release assets")
    urls = {a.get("name"): a.get("browser_download_url") for a in assets if isinstance(a, dict)}
    installer = urls.get(INSTALLER_NAME)
    checksums = urls.get(CHECKSUM_NAME)
    if not isinstance(installer, str) or not _safe_url(installer, asset=INSTALLER_NAME, tag=tag):
        # Earlier releases, including v0.4.5, have only a portable ZIP.
        installer = ""
        checksums = ""
    elif not isinstance(checksums, str) or not _safe_url(checksums, asset=CHECKSUM_NAME, tag=tag):
        raise ValueError("Official checksum asset missing")
    page = f"https://github.com/SLP-DEV1/PenX/releases/tag/{tag}"
    return Release(tag, installer, checksums, page)


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
            if final.scheme != "https" or final.hostname not in (
                "github.com", "release-assets.githubusercontent.com"
            ):
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
        # Avoid leaving executable partial downloads behind after any failure.
        target.unlink(missing_ok=True)
        raise


def check_update(*, quiet: bool = False) -> Release | None:
    try:
        latest = fetch_latest()
    except (OSError, ValueError, TimeoutError, json.JSONDecodeError) as exc:
        if not quiet:
            print(f"[WARN] Could not check GitHub Releases: {exc}")
        return None
    if not quiet:
        print(f"Installed PenX version: v{VERSION}")
        print(f"Latest stable GitHub release: {latest.tag}")
        if is_newer(latest):
            print(f"New release available: {latest.page_url}")
            if not latest.installer_url:
                print("This release has no Windows installer; download it manually.")
        else:
            print("[OK] PenX is up to date.")
    return latest if is_newer(latest) else None


def update_interactive() -> bool:
    """Only a positive explicit response can trigger an installer execution."""
    latest = check_update()
    if latest is None:
        return False
    if os.name != "nt" or not installed_mode() or not latest.installer_url:
        print(f"Open {latest.page_url} for the available download.")
        print("Automatic installation is only supported for the installed Windows edition.")
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
    """Best-effort once-per-day notice; no install/download and no portable traffic."""
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
    # Only a successful GitHub release lookup advances the throttle marker.
    # A transient network failure must be retried at the next startup.
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
