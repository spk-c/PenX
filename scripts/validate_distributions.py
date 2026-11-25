#!/usr/bin/env python3
"""Static consistency checks for pinned WinGet/Scoop draft manifests.

No network requests, scanners, external commands, or file modifications.
WinGet schema checks and installation tests must still run on Windows.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
WINGET_BASE = ROOT / "packaging" / "winget" / "manifests" / "s" / "SLP-DEV1" / "PenX"
SCOOP_FILE = ROOT / "packaging" / "scoop" / "penx.json"
ARCHIVE_NAME = "PenX-Windows-x64.zip"
INSTALLER_NAME = "PenX-Setup-x64.exe"
INSTALLER_PINS = {
    "0.6.1": "a99922e88a3a3c83b12bf017b7bae3eba68c8313bd547d58087aa53c383e602a",
}
ARCHIVE_PINS = {
    "0.6.1": "5d37fbc3d50e524d8335cb9b3b8ca5c8191d4e6216fb574ba009f2454d626e44",
}


def fail(message: str) -> None:
    raise ValueError(message)


def manifest_scalar(text: str, key: str) -> str:
    matches = re.findall(rf"(?m)^\s*(?:-\s+)?{re.escape(key)}:\s*(\S.*?)\s*$", text)
    if len(matches) != 1:
        fail(f"Expected one {key} entry, found {len(matches)}")
    return matches[0].strip().strip("'\"")


def main() -> int:
    try:
        scoop = json.loads(SCOOP_FILE.read_text(encoding="utf-8"))
        version = scoop["version"]
        archive = scoop["architecture"]["64bit"]
        expected_url = (
            f"https://github.com/spk-c/PenX/releases/download/v{version}/"
            f"{ARCHIVE_NAME}"
        )
        if archive["url"] != expected_url:
            fail("Scoop archive URL/version mismatch")
        checksum = archive["hash"]
        if not isinstance(checksum, str) or checksum.casefold() != ARCHIVE_PINS.get(version):
            fail("Scoop archive SHA-256 mismatch")
        if ["PenX\\PenX.exe", "penx"] not in scoop["bin"]:
            fail("Missing Scoop command shim")
        if "PenX\\.env" not in scoop["persist"]:
            fail("Scoop must persist configuration")
        if "PenX\\data" not in scoop["persist"]:
            fail("Scoop must persist scan database")
        if "PenX\\reports" not in scoop["persist"]:
            fail("Scoop must persist reports")
        folder = WINGET_BASE / version
        if not folder.is_dir():
            fail(f"Missing WinGet version folder {folder}")
        files = [
            folder / "SLP-DEV1.PenX.yaml",
            folder / "SLP-DEV1.PenX.installer.yaml",
            folder / "SLP-DEV1.PenX.locale.en-US.yaml",
        ]
        for path in files:
            if not path.is_file():
                fail(f"Missing WinGet manifest: {path}")
            content = path.read_text(encoding="utf-8")
            if manifest_scalar(content, "PackageIdentifier") != "SLP-DEV1.PenX":
                fail(f"Unexpected package ID in {path.name}")
            if manifest_scalar(content, "PackageVersion") != version:
                fail(f"Package version mismatch in {path.name}")
        root, installer, locale = [p.read_text(encoding="utf-8") for p in files]
        if manifest_scalar(root, "ManifestType") != "version":
            fail("Invalid WinGet version manifest type")
        if manifest_scalar(installer, "ManifestType") != "installer":
            fail("Invalid WinGet installer manifest type")
        if manifest_scalar(locale, "ManifestType") != "defaultLocale":
            fail("Invalid WinGet locale manifest type")
        if manifest_scalar(installer, "InstallerType") != "inno":
            fail("WinGet installer type must be inno")
        if manifest_scalar(installer, "Scope") != "user":
            fail("WinGet installer scope must be user")
        if manifest_scalar(installer, "ProductCode") != "{FCF9D8F6-64E9-4783-8E7F-9106E194C841}_is1":
            fail("WinGet installer product code mismatch")
        if manifest_scalar(installer, "InstallerUrl") != expected_url.removesuffix(ARCHIVE_NAME) + INSTALLER_NAME:
            fail("WinGet installer URL/version mismatch")
        if manifest_scalar(installer, "InstallerSha256").casefold() != INSTALLER_PINS.get(version):
            fail("WinGet installer SHA-256 mismatch")
        print(f"[OK] WinGet uses the pinned v{version} installer and Scoop uses the official ZIP")
    except (ValueError, KeyError, OSError, TypeError, json.JSONDecodeError) as exc:
        print(f"[FAIL] Package manifests: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
