"""Explicit inventory and distribution-native installed/fixed version comparison.

This module never discovers or executes commands on remote machines.
An admin must supply a matching inventory of source package names and exact
installed package versions. If data is missing or ambiguous, return unknown.
"""
from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path

MAX_INVENTORY_BYTES = 250_000
MAX_INVENTORY_PACKAGES = 2000
_ALLOWED = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+._~-]{0,99}$")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:.+~^_-]{0,179}$")
_RPM_EVR = re.compile(r"^(?:(\d+):)?([A-Za-z0-9][A-Za-z0-9._+~^-]*)-([A-Za-z0-9][A-Za-z0-9._+~^-]*)$")

class InventoryError(ValueError):
    pass

def load_inventory(path: str) -> dict:
    """Read user-provided machine inventory; never infer package data from banners."""
    if not path:
        return {}
    src = Path(path).expanduser()
    # A path may change between stat() and json.load(). Open only once,
    # reject symlinks and read at most one byte beyond the declared bound.
    fd = os.open(src, os.O_RDONLY | getattr(os, "O_BINARY", 0)
                 | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as handle:
        opened = os.fstat(handle.fileno())
        named = src.lstat()
        if (not stat.S_ISREG(opened.st_mode) or not stat.S_ISREG(named.st_mode)
                or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)):
            raise InventoryError("Package inventory must be a regular, non-symlink file.")
        if opened.st_size > MAX_INVENTORY_BYTES:
            raise InventoryError("Package inventory exceeds 250 KB.")
        data = handle.read(MAX_INVENTORY_BYTES + 1)
    if len(data) > MAX_INVENTORY_BYTES:
        raise InventoryError("Package inventory exceeds 250 KB.")
    info = json.loads(data.decode("utf-8"))
    if not isinstance(info, dict) or not isinstance(info.get("packages"), list):
        raise InventoryError("Expected JSON object with packages list.")
    distro, release = str(info.get("distro", "")).lower(), str(info.get("release", "")).lower()
    if distro not in ("ubuntu", "debian", "rhel") or not _ALLOWED.fullmatch(release):
        raise InventoryError("Inventory must include a supported distro and exact release.")
    packages = info["packages"]
    if len(packages) > MAX_INVENTORY_PACKAGES:
        raise InventoryError("Too many packages (maximum 2000).")
    indexed: dict[str, str] = {}
    for item in packages:
        if not isinstance(item, dict):
            raise InventoryError("Every package entry must be an object.")
        source = str(item.get("source", "")).lower()
        version = str(item.get("version", ""))
        if not _ALLOWED.fullmatch(source) or not _VERSION.fullmatch(version):
            raise InventoryError("Package source or version is not valid.")
        if source in indexed and indexed[source] != version:
            raise InventoryError("Conflicting installed versions for source package " + source)
        indexed[source] = version
    return {"distro": distro, "release": release, "packages": indexed}

def compare_deb_version(installed: str, fixed: str) -> int | None:
    """Use Debian's own algorithm, including epochs, tildes and revisions."""
    try:
        from debian.debian_support import Version
        if not _VERSION.fullmatch(installed) or not _VERSION.fullmatch(fixed):
            return None
        a, b = Version(installed), Version(fixed)
        return -1 if a < b else 1 if a > b else 0
    except (ValueError, TypeError, ImportError):
        return None

def compare_rpm_version(installed: str, fixed: str) -> int | None:
    """Compare canonical epoch:version-release strings, not arbitrary RPM filenames.

    rpm_vercmp is cross-platform but predates RPM caret semantics, so those
    newer versions must be reviewed with the distro's package manager.
    """
    try:
        import rpm_vercmp
    except ImportError:
        return None
    a, b = _RPM_EVR.fullmatch(installed), _RPM_EVR.fullmatch(fixed)
    if not a or not b or "^" in installed + fixed:
        return None
    ea, eb = int(a.group(1) or "0"), int(b.group(1) or "0")
    if ea != eb:
        return (ea > eb) - (ea < eb)
    vc = rpm_vercmp.vercmp(a.group(2), b.group(2))
    if vc:
        return (vc > 0) - (vc < 0)
    rc = rpm_vercmp.vercmp(a.group(3), b.group(3))
    return (rc > 0) - (rc < 0)

def compare_installed(installed: str, fixed: str, distro: str) -> str:
    """A version-order conclusion, not a claim that the service is exploitable."""
    result = compare_rpm_version(installed, fixed) if distro == "rhel" else (
        compare_deb_version(installed, fixed) if distro in ("debian", "ubuntu") else None
    )
    return ("unknown-version-comparison" if result is None else
            "below-published-fix" if result < 0 else "at-or-above-published-fix")

def package_status(source: str, fixed: str, inventory: dict) -> dict:
    """Attach independent install evidence only on exact source-package identity."""
    installed = inventory.get("packages", {}).get(source.lower())
    if not installed:
        return {"installed_status": "no-exact-package-match"}
    status = compare_installed(installed, fixed, inventory["distro"])
    return {"installed_status": status, "installed_version": installed,
            "compared_fix_version": fixed,
            "comparison_note": "Version comparison only; verify vendor advisory and installed build."}
