#!/usr/bin/env python3
"""Deterministic offline SBOM and build-manifest tooling for PenX releases (PX-005).

Commands:
  sbom          Generate a CycloneDX 1.5 JSON SBOM from the hash-locked
                runtime requirements and the declared build-tool requirement.
  manifest      Generate a build manifest recording the exact commit, tag,
                event, platform, asset sizes and SHA-256 hashes of a release.
  verify-release  Verify a release bundle fully offline: asset files,
                SHA256SUMS files, manifest and SBOM inventory must all agree.

No network access, no third-party dependencies, no signing claims: the
manifest always records ``"signing": {"scheme": "none"}``.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))
from penx_app.version import VERSION  # noqa: E402

SBOM_FORMAT = "CycloneDX 1.5"
SBOM_NAME = "PenX-SBOM.json"
MANIFEST_NAME = "PenX-BUILD-MANIFEST.json"
MANIFEST_ID = "penx-build-manifest-v1"
BUILD_WORKFLOW = ".github/workflows/release.yml"
NO_SIGNING = {
    "scheme": "none",
    "claims": ("No Authenticode, sigstore, or other cryptographic signature is "
               "asserted. Verification is SHA-256 based against this manifest."),
}

_Package = Tuple[str, str, Tuple[str, ...]]  # name, version, sha256 hashes
_SHA256SUMS_RE = re.compile(r"^([a-f0-9]{64})  \*?(\S+)$")
_LOCK_PKG_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([0-9][A-Za-z0-9.!+*-]*)\s*\\?\s*$")
_HASH_RE = re.compile(r"^--hash=sha256:([a-f0-9]{64})\s*\\?\s*$")
_BUILD_REQ_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?([=<>!~]=.*)?$")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _deterministic_json(document: dict) -> str:
    return json.dumps(document, indent=2, sort_keys=True) + "\n"


def write_deterministic_json(path: Path, document: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_deterministic_json(document), encoding="utf-8", newline="\n")


# --------------------------------------------------------------------------
# Requirement inventories (offline, file-based only)
# --------------------------------------------------------------------------

def parse_locked_requirements(path: Path) -> List[_Package]:
    """Parse a pip-compile lock file into (name, version, sha256 hashes)."""
    packages: Dict[str, _Package] = {}
    current: Optional[_Package] = None
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = _HASH_RE.match(line)
        if match:
            if current is None:
                raise ValueError("Hash line before any package entry")
            name, version, hashes = current
            current = (name, version, hashes + (match.group(1),))
            packages[name.lower()] = current
            continue
        match = _LOCK_PKG_RE.match(line)
        if match:
            current = (match.group(1), match.group(2), ())
            packages[current[0].lower()] = current
            continue
        raise ValueError(f"Unrecognized lock file line: {line!r}")
    return sorted(packages.values(), key=lambda item: item[0].lower())


def parse_build_requirements(path: Path) -> List[Tuple[str, str]]:
    """Parse requirements-build.txt into (name, declared specifier)."""
    entries: List[Tuple[str, str]] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = _BUILD_REQ_RE.match(line)
        if not match or not line:
            raise ValueError(f"Unrecognized build requirement line: {line!r}")
        name = match.group(1)
        specifier = (match.group(2) or "") + (match.group(3) or "")
        entries.append((name, specifier))
    return entries


# --------------------------------------------------------------------------
# SBOM (CycloneDX 1.5)
# --------------------------------------------------------------------------

def _pypi_purl(name: str, version: Optional[str]) -> str:
    purl = "pkg:pypi/" + name.lower()
    if version:
        purl += "@" + version
    return purl


def build_sbom(version: str, runtime: List[_Package],
               build: List[Tuple[str, str]]) -> dict:
    """Build a deterministic CycloneDX 1.5 document.

    No serialNumber or timestamp: byte-identical input lock files produce
    byte-identical output.
    """
    components: List[Dict[str, object]] = []
    for name, package_version, hashes in runtime:
        purl = _pypi_purl(name, package_version)
        components.append({
            "bom-ref": purl,
            "name": name,
            "purl": purl,
            "type": "library",
            "version": package_version,
            "hashes": [{"alg": "sha256", "value": value}
                       for value in sorted(hashes)],
            "properties": [{"name": "penx:role", "value": "runtime"}],
        })
    for name, specifier in build:
        component: Dict[str, object] = {
            "bom-ref": "penx-build:" + name.lower(),
            "name": name,
            "purl": _pypi_purl(name, None),
            "type": "library",
            "properties": [
                {"name": "penx:role", "value": "build"},
                {"name": "penx:declared", "value": specifier or "any"},
            ],
        }
        components.append(component)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "metadata": {
            "tools": [{"vendor": "PenX", "name": "release_supply_chain.py"}],
            "component": {
                "type": "application",
                "name": "penx",
                "version": version,
                "purl": f"pkg:github/spk-c/PenX@v{version}",
            },
        },
        "components": components,
    }


def generate_sbom(output: Path, lockfile: Path, buildfile: Path) -> dict:
    document = build_sbom(VERSION, parse_locked_requirements(lockfile),
                          parse_build_requirements(buildfile))
    write_deterministic_json(output, document)
    return document


# --------------------------------------------------------------------------
# Build manifest
# --------------------------------------------------------------------------

def platform_for_asset(name: str) -> str:
    if name == "PenX-Windows-x64.zip" or name == "PenX-Setup-x64.exe":
        return "windows-x64"
    if name == "PenX-Linux-x86_64.tar.gz":
        return "linux-x86_64"
    match = re.fullmatch(r"penx_[0-9]+\.[0-9]+\.[0-9]+_([a-z0-9]+)\.deb", name)
    if match:
        return "linux-" + match.group(1)
    raise ValueError(f"Unknown release asset name: {name!r}")


def build_manifest(*, version: str, repository: str, commit: str, event: str,
                   ref: str, python_version: str,
                   assets: List[Path], sbom_path: Path) -> dict:
    """Build the deterministic build-manifest document for a release bundle."""
    entries: List[Dict[str, object]] = []
    for path in assets:
        name = path.name
        entries.append({
            "name": name,
            "platform": platform_for_asset(name),
            "size_bytes": path.stat().st_size,
            "sha256": _sha256_file(path),
        })
    entries.sort(key=lambda item: str(item["name"]))
    return {
        "manifest": MANIFEST_ID,
        "product": "penx",
        "version": version,
        "repository": repository,
        "commit": commit,
        "event": event,
        "ref": ref,
        "build_workflow": BUILD_WORKFLOW,
        "python": python_version,
        "assets": entries,
        "sbom": {
            "file": SBOM_NAME,
            "format": SBOM_FORMAT,
            "sha256": _sha256_file(sbom_path),
        },
        "signing": NO_SIGNING,
    }


def generate_manifest(output: Path, sbom: Path, assets: List[Path],
                      commit: Optional[str], event: Optional[str],
                      ref: Optional[str], repository: Optional[str],
                      python_version: Optional[str]) -> dict:
    document = build_manifest(
        version=VERSION,
        repository=repository or os.environ.get("GITHUB_REPOSITORY", "spk-c/PenX"),
        commit=commit or os.environ.get("GITHUB_SHA", ""),
        event=event or os.environ.get("GITHUB_EVENT_NAME", "manual"),
        ref=ref or os.environ.get("GITHUB_REF_NAME", ""),
        python_version=python_version or sys.version.split()[0],
        assets=assets,
        sbom_path=sbom,
    )
    if not re.fullmatch(r"[0-9a-f]{40}", document["commit"]):
        raise ValueError("commit must be a 40-character lowercase SHA")
    write_deterministic_json(output, document)
    return document


# --------------------------------------------------------------------------
# Offline release-bundle verification
# --------------------------------------------------------------------------

def parse_sha256sums(path: Path) -> Dict[str, str]:
    entries: Dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = _SHA256SUMS_RE.match(line)
        if not match:
            raise ValueError(f"Malformed SHA256SUMS line: {line!r}")
        name = match.group(2)
        if name in entries:
            raise ValueError(f"Duplicate SHA256SUMS entry: {name}")
        entries[name] = match.group(1)
    return entries


def _unique_by_name(directory: Path, name: str) -> List[Path]:
    return sorted(p for p in directory.rglob(name) if p.is_file())


def verify_release(directory: Path, *, expect_version: Optional[str] = None,
                   expect_commit: Optional[str] = None,
                   lockfile: Optional[Path] = None) -> List[Tuple[str, str]]:
    """Verify a release bundle offline. Returns (level, message) pairs."""
    directory = Path(directory)
    findings: List[Tuple[str, str]] = []

    def check(ok: bool, message: str) -> None:
        findings.append(("OK" if ok else "FAIL", message))

    manifest_path = directory / MANIFEST_NAME
    if not manifest_path.is_file():
        return [("FAIL", f"Missing {MANIFEST_NAME}")]
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [("FAIL", f"Unreadable manifest: {exc}")]

    check(manifest.get("manifest") == MANIFEST_ID,
          f"Manifest id is {MANIFEST_ID} (found {manifest.get('manifest')!r})")
    version = manifest.get("version")
    ref = manifest.get("ref", "")
    commit = manifest.get("commit", "")
    check(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version or "") is not None,
          f"Manifest version {version!r} is a safe semver")
    if manifest.get("event") == "push":
        check(ref == f"v{version}",
              f"Manifest ref {ref!r} matches v{version} for a push event")
    check(re.fullmatch(r"[0-9a-f]{40}", commit) is not None,
          f"Manifest commit {commit!r} is a 40-character SHA")
    check(manifest.get("signing", {}).get("scheme") == "none",
          "Manifest signing scheme is none (no signature claims)")
    if expect_version is not None:
        check(version == expect_version,
              f"Manifest version {version!r} matches expected {expect_version!r}")
    if expect_commit is not None:
        check(commit == expect_commit,
              f"Manifest commit matches expected {expect_commit!r}")

    assets = manifest.get("assets") or []
    check(len(assets) == len({a.get("name") for a in assets}),
          "Manifest asset names are unique")
    for entry in assets:
        name = entry.get("name", "?")
        matches = _unique_by_name(directory, name)
        if len(matches) != 1:
            check(False, f"Asset {name!r} is found exactly once "
                         f"(found {len(matches)})")
            continue
        path = matches[0]
        actual = _sha256_file(path)
        check(actual == entry.get("sha256"), f"SHA256 matches: {name}")
        check(path.stat().st_size == entry.get("size_bytes"),
              f"Size matches: {name}")
        try:
            check(platform_for_asset(name) == entry.get("platform"),
                  f"Platform matches: {name}")
        except ValueError:
            check(False, f"Platform mapping known: {name!r}")

    windows = sorted(a["name"] for a in assets
                    if a.get("platform") == "windows-x64")
    linux = sorted(a["name"] for a in assets
                  if str(a.get("platform", "")).startswith("linux"))
    sums_windows = _unique_by_name(directory, "SHA256SUMS.txt")
    if len(sums_windows) != 1:
        check(False, f"SHA256SUMS.txt is found exactly once "
                    f"(found {len(sums_windows)})")
    else:
        try:
            expected = parse_sha256sums(sums_windows[0])
            check(sorted(expected) == windows,
                  f"SHA256SUMS.txt covers exactly the Windows assets {windows}")
            for name, digest in expected.items():
                entry = next(a for a in assets if a["name"] == name)
                check(digest == entry["sha256"],
                      f"SHA256SUMS.txt digest matches: {name}")
        except (OSError, ValueError) as exc:
            check(False, f"SHA256SUMS.txt is valid ({exc})")
    sums_linux = _unique_by_name(directory, "SHA256SUMS-Linux.txt")
    if len(sums_linux) != 1:
        check(False, f"SHA256SUMS-Linux.txt is found exactly once "
                    f"(found {len(sums_linux)})")
    else:
        try:
            expected = parse_sha256sums(sums_linux[0])
            check(sorted(expected) == linux,
                  f"SHA256SUMS-Linux.txt covers exactly the Linux assets {linux}")
            for name, digest in expected.items():
                entry = next(a for a in assets if a["name"] == name)
                check(digest == entry["sha256"],
                      f"SHA256SUMS-Linux.txt digest matches: {name}")
        except (OSError, ValueError) as exc:
            check(False, f"SHA256SUMS-Linux.txt is valid ({exc})")

    sbom_entry = manifest.get("sbom") or {}
    sbom_matches = _unique_by_name(directory, sbom_entry.get("file", SBOM_NAME))
    if len(sbom_matches) != 1:
        check(False, f"SBOM {SBOM_NAME!r} found {len(sbom_matches)} times")
    else:
        sbom_path = sbom_matches[0]
        check(_sha256_file(sbom_path) == sbom_entry.get("sha256"),
              f"SHA256 matches: {SBOM_NAME}")
        try:
            document = json.loads(sbom_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            document = {}
            check(False, f"SBOM is readable ({exc})")
        check(document.get("bomFormat") == "CycloneDX"
              and document.get("specVersion") == "1.5",
              "SBOM is CycloneDX 1.5")
        component = (document.get("metadata") or {}).get("component", {})
        check(component.get("name") == "penx"
              and component.get("version") == version,
              "SBOM application component matches manifest version")
        lockfile = lockfile if lockfile is not None else ROOT / "requirements.lock.txt"
        try:
            locked = parse_locked_requirements(lockfile)
            sbom_runtime = {
                (c.get("name", "").lower(), c.get("version", ""))
                for c in document.get("components", [])
                if any(p.get("name") == "penx:role" and p.get("value") == "runtime"
                       for p in c.get("properties", []))
            }
            locked_set = {(n.lower(), v) for n, v, _ in locked}
            check(sbom_runtime == locked_set,
                  "SBOM runtime inventory matches requirements.lock.txt")
        except (OSError, ValueError) as exc:
            check(False, f"requirements.lock.txt is verifiable ({exc})")
    return findings


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _cmd_sbom(args: argparse.Namespace) -> int:
    output = Path(args.output)
    generate_sbom(output, Path(args.lockfile), Path(args.buildfile))
    print(f"[OK] Wrote {output} (CycloneDX 1.5)")
    return 0


def _cmd_manifest(args: argparse.Namespace) -> int:
    sbom = Path(args.sbom)
    if not sbom.is_file():
        print(f"[FAIL] SBOM not found: {sbom}", file=sys.stderr)
        return 2
    assets = [Path(p) for p in args.asset]
    missing = [str(p) for p in assets if not p.is_file()]
    if missing:
        print("[FAIL] Missing asset files: " + ", ".join(missing),
              file=sys.stderr)
        return 2
    try:
        generate_manifest(Path(args.output), sbom, assets,
                          commit=args.commit, event=args.event,
                          ref=args.ref, repository=args.repository,
                          python_version=None)
    except ValueError as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 2
    print(f"[OK] Wrote {args.output} (build manifest)")
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    findings = verify_release(Path(args.directory),
                              expect_version=args.expect_version,
                              expect_commit=args.expect_commit,
                              lockfile=Path(args.lockfile)
                              if args.lockfile else None)
    for level, message in findings:
        print(f"[{level}] {message}")
    failed = sum(level == "FAIL" for level, _ in findings)
    print(f"[{'FAIL' if failed else 'OK'}] "
          f"{len(findings) - failed}/{len(findings)} checks passed")
    return 1 if failed else 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Offline SBOM and build-manifest tooling for PenX releases.")
    sub = parser.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("sbom", help="Generate the CycloneDX 1.5 SBOM")
    sp.add_argument("--output", default=SBOM_NAME)
    sp.add_argument("--lockfile", default=str(ROOT / "requirements.lock.txt"))
    sp.add_argument("--buildfile", default=str(ROOT / "requirements-build.txt"))
    sp.set_defaults(func=_cmd_sbom)

    sp = sub.add_parser("manifest", help="Generate the build manifest")
    sp.add_argument("--output", default=MANIFEST_NAME)
    sp.add_argument("--sbom", default=SBOM_NAME)
    sp.add_argument("--asset", action="append", default=[], required=True)
    sp.add_argument("--commit", default=None)
    sp.add_argument("--event", default=None)
    sp.add_argument("--ref", default=None)
    sp.add_argument("--repository", default=None)
    sp.set_defaults(func=_cmd_manifest)

    sp = sub.add_parser("verify-release",
                        help="Verify a release bundle directory offline")
    sp.add_argument("directory")
    sp.add_argument("--expect-version", default=None)
    sp.add_argument("--expect-commit", default=None)
    sp.add_argument("--lockfile", default=None)
    sp.set_defaults(func=_cmd_verify)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
