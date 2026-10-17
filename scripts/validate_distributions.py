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
        assert archive["url"] == expected_url, "Scoop archive URL/version mismatch"
        assert SHA_PATTERN.fullmatch(archive["hash"]), "Invalid Scoop archive SHA-256"
        assert ["PenX\\PenX.exe", "penx"] in scoop["bin"], "Missing Scoop command shim"
        assert "PenX\\.env" in scoop["persist"], "Scoop must persist configuration"
        assert "PenX\\data" in scoop["persist"], "Scoop must persist scan database"
        assert "PenX\\reports" in scoop["persist"], "Scoop must persist reports"
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
            assert manifest_scalar(content, "PackageIdentifier") == "SLP-DEV1.PenX"
            assert manifest_scalar(content, "PackageVersion") == version
        root, installer, locale = [p.read_text(encoding="utf-8") for p in files]
        assert manifest_scalar(root, "ManifestType") == "version"
        assert manifest_scalar(installer, "ManifestType") == "installer"
        assert manifest_scalar(locale, "ManifestType") == "defaultLocale"
        assert manifest_scalar(installer, "InstallerType") == "zip"
        assert manifest_scalar(installer, "NestedInstallerType") == "portable"
        assert manifest_scalar(installer, "InstallerUrl") == expected_url
        assert manifest_scalar(installer, "InstallerSha256").casefold() == archive["hash"].casefold()
        assert manifest_scalar(installer, "RelativeFilePath") == "PenX/PenX.exe"
        assert manifest_scalar(installer, "PortableCommandAlias") == "penx"
        print(f"[OK] WinGet/Scoop drafts pin v{version} to one official ZIP and SHA-256")
    except (AssertionError, ValueError, KeyError, OSError, TypeError, json.JSONDecodeError) as exc:
        print(f"[FAIL] Package manifests: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
