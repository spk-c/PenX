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
SHA_PATTERN = re.compile(r"[a-fA-F0-9]{64}\Z")


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
        if not SHA_PATTERN.fullmatch(archive["hash"]):
            fail("Invalid Scoop archive SHA-256")
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
        if manifest_scalar(installer, "InstallerType") != "zip":
            fail("WinGet installer type must be zip")
        if manifest_scalar(installer, "NestedInstallerType") != "portable":
            fail("WinGet nested installer type must be portable")
        if manifest_scalar(installer, "InstallerUrl") != expected_url:
            fail("WinGet installer URL/version mismatch")
        if manifest_scalar(installer, "InstallerSha256").casefold() != archive["hash"].casefold():
            fail("WinGet/Scoop SHA-256 mismatch")
        if manifest_scalar(installer, "RelativeFilePath") != "PenX/PenX.exe":
            fail("WinGet portable executable path mismatch")
        if manifest_scalar(installer, "PortableCommandAlias") != "penx":
            fail("WinGet portable command alias mismatch")
        print(f"[OK] WinGet/Scoop drafts pin v{version} to one official ZIP and SHA-256")
    except (AssertionError, ValueError, KeyError, OSError, TypeError, json.JSONDecodeError) as exc:
        print(f"[FAIL] Package manifests: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
