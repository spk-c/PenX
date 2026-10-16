"""Opt-in SHA256-verified portable Windows scanner installer.

Fetch release metadata from official GitHub repositories. Download an exact
windows_amd64 zip asset, verify GitHub's SHA256 digest, and extract ONLY the
requested .exe to PenX/vendor/bin. Never execute downloaded files during setup.
"""
from __future__ import annotations

import hashlib
import io
import os
from pathlib import Path
import platform
import re
import subprocess
import tempfile
import zipfile
from urllib.parse import urlsplit

import requests

from penx_app.app_paths import APP_ROOT
from penx_app.scanners.native_web_scanners import find_native, nuclei_templates, has_nuclei_templates, template_install_directory

SOURCES = {
    "nuclei": "projectdiscovery/nuclei",
    "httpx": "projectdiscovery/httpx",
    "ffuf": "ffuf/ffuf",
    "subfinder": "projectdiscovery/subfinder",
    "katana": "projectdiscovery/katana",
}
MAX_DOWNLOAD = 100 * 1024 * 1024
MAX_BINARY = 180 * 1024 * 1024


def _asset_for(name: str, metadata: dict) -> dict:
    if not isinstance(metadata, dict):
        raise ValueError("Invalid GitHub release metadata")
    pattern = re.compile(rf"^{re.escape(name)}_[0-9][0-9A-Za-z._-]*_windows_amd64\.zip$")
    for asset in metadata.get("assets", []):
        if not pattern.fullmatch(str(asset.get("name", ""))):
            continue
        digest = str(asset.get("digest", ""))
        download_url = str(asset.get("browser_download_url", ""))
        if not re.fullmatch(r"sha256:[0-9a-fA-F]{64}", digest):
            raise ValueError("Release asset has no verifiable SHA256 digest")
        if not download_url.startswith("https://github.com/" + SOURCES[name] + "/releases/download/"):
            raise ValueError("Unexpected release asset URL")
        if int(asset.get("size", MAX_DOWNLOAD + 1)) > MAX_DOWNLOAD:
            raise ValueError("Release asset exceeds size limit")
        return {"url": download_url, "digest": digest.split(":", 1)[1].lower()}
    raise ValueError("No Windows amd64 ZIP release asset was found")


def _http_get(url: str, *, stream: bool = False):
    """Refuse HTTPS downgrades and redirects outside GitHub's asset CDN."""
    response = requests.get(
        url,
        headers={"Accept": "application/vnd.github+json",
                 "User-Agent": "PenX-NativeSetup/1.0"},
        timeout=(5, 40),
        stream=stream,
    )
    # requests follows redirects by default; validate the actual final origin.
    final_url = urlsplit(str(response.url or ""))
    host = (final_url.hostname or "").lower()
    authorized = host in {"api.github.com", "github.com"} or host.endswith(".githubusercontent.com")
    if final_url.scheme != "https" or not authorized:
        response.close()
        raise ValueError("Native scanner download redirected to an unapproved origin")
    return response


def download_verified_exe(name: str, *, destination: Path | None = None) -> Path:
    """Download safely; installer caller must obtain explicit user consent."""
    if name not in SOURCES:
        raise ValueError("Unsupported scanner name")
    if os.name != "nt" or platform.machine().lower() not in ("amd64", "x86_64"):
        raise OSError("Portable installer currently supports Windows x64 only")
    dest = destination or APP_ROOT / "vendor" / "bin"
    metadata_url = "https://api.github.com/repos/" + SOURCES[name] + "/releases/latest"
    metadata_response = _http_get(metadata_url)
    try:
        metadata_response.raise_for_status()
        release = metadata_response.json()
    finally:
        metadata_response.close()
    asset = _asset_for(name, release)
    response = _http_get(asset["url"], stream=True)
    try:
        response.raise_for_status()
        total = 0
        checksum = hashlib.sha256()
        archive = io.BytesIO()
        for block in response.iter_content(chunk_size=65536):
            total += len(block)
            if total > MAX_DOWNLOAD:
                raise ValueError("Release download exceeds size limit")
            checksum.update(block)
            archive.write(block)
    finally:
        response.close()
    if checksum.hexdigest() != asset["digest"]:
        raise ValueError("SHA256 verification failed; binary was not installed")

    with zipfile.ZipFile(io.BytesIO(archive.getvalue())) as bundle:
        matches = [info for info in bundle.infolist()
                   if Path(info.filename.replace("\\", "/")).name.lower() == name + ".exe"
                   and not info.is_dir()]
        if len(matches) != 1 or matches[0].file_size > MAX_BINARY:
            raise ValueError("Release archive has an unexpected executable layout")
        info = matches[0]
        # Never extract archive paths. Copy only the uniquely named executable
        # and replace it atomically after the verified ZIP is fully inspected.
        dest.mkdir(parents=True, exist_ok=True)
        output = dest / (name + ".exe")
        if output.exists():
            raise FileExistsError(f"Scanner already installed at {output}")
        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(mode="w+b", dir=dest, prefix=".penx_", suffix=".tmp",
                                             delete=False) as temp:
                tmp_path = Path(temp.name)
                with bundle.open(info) as executable:
                    signature = executable.read(2)
                    if signature != b"MZ":
                        raise ValueError("Asset is not a Windows executable")
                    temp.write(signature)
                    transferred = 2
                    while True:
                        data = executable.read(65536)
                        if not data:
                            break
                        transferred += len(data)
                        if transferred > MAX_BINARY:
                            raise ValueError("Executable exceeds size limit")
                        temp.write(data)
            # Hard-link the complete temporary EXE into place atomically.
            # Unlike os.replace(), os.link() refuses an existing destination:
            # concurrent installers must never overwrite user-managed binaries.
            try:
                os.link(tmp_path, output)
            except FileExistsError as exc:
                raise FileExistsError("Scanner was installed concurrently") from exc
        finally:
            if tmp_path and tmp_path.exists():
                tmp_path.unlink()
        return output


def install_nuclei_templates(executable: str, directory: Path) -> bool:
    """Run the official template updater only during explicitly authorized setup.

    The initial community-template download can take longer than 180 seconds.
    Never run this updater during an active target scan. A timeout is reported
    as incomplete even if partial YAML files appeared on disk.
    """
    try:
        timeout = int(os.getenv("PENX_NUCLEI_TEMPLATE_TIMEOUT", "600"))
    except ValueError:
        timeout = 600
    timeout = max(180, min(timeout, 1200))
    try:
        directory.mkdir(parents=True, exist_ok=True)
        marker = directory / ".penx-template-update-incomplete"
        marker.write_text("Installer has not completed the template update.\\n", encoding="utf-8")
        print(f"[*] Updating Nuclei templates (allow up to {timeout}s): {directory}", flush=True)
        outcome = subprocess.run(
            [executable, "-update-templates", "-update-template-dir", str(directory)],
            capture_output=True, text=True, shell=False, check=False, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        print(f"[WARN] Nuclei template updater exceeded {timeout}s. "
              "Its download may be slow or the network may be blocking GitHub.", flush=True)
        partial = exc.stderr or exc.stdout
        if partial:
            detail = (partial.decode("utf-8", errors="replace") if isinstance(partial, bytes)
                      else str(partial))
            print("[WARN] Nuclei updater output: " + detail.strip()[-400:], flush=True)
        print("[INFO] Templates are not marked ready after a timed-out update. "
              "Retry installer or set PENX_NUCLEI_TEMPLATE_TIMEOUT up to 1200 seconds.")
        return False
    except OSError as exc:
        print(f"[WARN] Cannot install Nuclei templates: {exc}", flush=True)
        return False
    if outcome.returncode:
        detail = (outcome.stderr or outcome.stdout or "").strip()[-500:]
        print(f"[WARN] Nuclei updater exited with code {outcome.returncode}: {detail}")
        return False
    if not has_nuclei_templates(directory, allow_incomplete=True):
        print(f"[WARN] Nuclei updater finished, but no YAML templates were found in {directory}.")
        return False
    try:
        marker.unlink()
    except OSError as exc:
        print(f"[WARN] Cannot finalize Nuclei template installation: {exc}")
        return False
    print(f"[OK] Nuclei templates installed: {directory}")
    return True

def main() -> int:
    print("Optional PenX native scanners (Windows x64, no shell/WSL required):")
    missing = []
    for name in SOURCES:
        present = find_native(name)
        print(f"  {name}: {present or 'not installed'}")
        if not present:
            missing.append(name)
    failures = 0
    if missing:
        print("Download official releases with GitHub SHA256 digest verification?")
        print("Only approved repositories are used. No scanner is executed during installation.")
        try:
            confirm = input("Install missing native scanners now? [y/N]: ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            return 0
        if confirm in ("y", "yes", "j", "ja"):
            for name in missing:
                try:
                    path = download_verified_exe(name)
                    print(f"[OK] Installed {name}: {path}")
                except (requests.RequestException, OSError, ValueError, zipfile.BadZipFile) as exc:
                    print(f"[WARN] Could not install {name}: {exc}")
                    failures += 1
        else:
            print("[INFO] No executables were downloaded.")
    else:
        print("[OK] Native scanner executables are present.")

    nuclei = find_native("nuclei")
    if nuclei and nuclei_templates() is None:
        print("Nuclei has no templates. Download official nuclei-templates separately?")
        print("Templates are maintained externally; review and update them before use.")
        try:
            consent = input("Install Nuclei templates now? [y/N]: ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            consent = ""
        if consent in ("y", "yes", "j", "ja"):
            if not install_nuclei_templates(nuclei, template_install_directory()):
                failures += 1
        else:
            print("[INFO] Nuclei scans remain unavailable until templates are installed.")
    return 1 if failures else 0
