"""PX-304 deterministic local SBOM inventory only, with no vulnerability verdict.

Accept explicitly supplied CycloneDX 1.5/1.6 or SPDX 2.3 JSON. Only exact,
unqualified PyPI and npm package URLs become normalized package identities.
Missing, unsupported or ambiguous provenance remains unresolved, not "safe".
No requests, disclosure or automatic advisory lookups are made.
"""
from __future__ import annotations

from collections import Counter
import json
import os
from pathlib import Path
import re
import stat
from urllib.parse import unquote

MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_COMPONENTS = 2000
MAX_NAME_CHARS = 160
MAX_VERSION_CHARS = 120
_ALLOWED_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+_~-]{0,119}\Z")
_PURL = re.compile(r"pkg:([A-Za-z][A-Za-z0-9.+-]*)/([^?#]+)\Z")
_INVALID_PERCENT = re.compile(r"%(?![0-9a-fA-F]{2})")
_PYPI = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_NPM = re.compile(r"(?:@[a-z0-9][a-z0-9._~-]{0,63}/)?[a-z0-9][a-z0-9._~-]{0,127}\Z")


class SBOMError(ValueError):
    """Invalid or unsupported local SBOM fixture."""


def _unique_json_object(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise SBOMError("Repeated SBOM JSON field")
        result[name] = value
    return result


def _reject_json_constant(_text):
    raise SBOMError("Non-JSON numeric constant")


def _load_file(path: str | Path):
    if not isinstance(path, (str, Path)) or not str(path):
        raise SBOMError("Explicit local SBOM path required")
    item = Path(path).expanduser()
    fd = os.open(item, os.O_RDONLY | getattr(os, "O_BINARY", 0)
                 | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as stream:
        handle_stat = os.fstat(stream.fileno())
        named_stat = item.lstat()
        if (not stat.S_ISREG(handle_stat.st_mode)
                or not stat.S_ISREG(named_stat.st_mode)
                or (handle_stat.st_dev, handle_stat.st_ino)
                != (named_stat.st_dev, named_stat.st_ino)):
            raise SBOMError("SBOM must be an existing regular non-symlink file")
        if handle_stat.st_size > MAX_FILE_BYTES:
            raise SBOMError("SBOM exceeds size limit")
        raw = stream.read(MAX_FILE_BYTES + 1)
    if not raw or len(raw) > MAX_FILE_BYTES:
        raise SBOMError("Empty or oversized SBOM")
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_json_object,
                              parse_constant=_reject_json_constant)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise SBOMError("Invalid SBOM JSON") from exc
    if not isinstance(document, dict):
        raise SBOMError("SBOM root must be a JSON object")
    return document


def _safe_label(value: object, *, max_chars: int) -> str:
    if (not isinstance(value, str) or not 1 <= len(value) <= max_chars
            or any(ord(ch) < 32 or ord(ch) == 127 for ch in value)):
        raise SBOMError("Invalid SBOM package name or version")
    return value


def _exact_package_url(value: object, *, version: str) -> tuple[str, str, str] | None:
    if value is None or value == "":
        return None
    _safe_label(value, max_chars=400)
    if _INVALID_PERCENT.search(value):
        raise SBOMError("Malformed percent escape in package URL")
    match = _PURL.fullmatch(value)
    if match is None:
        # URL qualifiers/subpaths mean identity is not *exact* in this
        # small importer. Never silently strip them for exposure matching.
        return None
    kind, identifier = match.groups()
    if "@" not in identifier:
        return None
    encoded_name, encoded_version = identifier.rsplit("@", 1)
    if not encoded_name or not encoded_version:
        return None
    decoded_version = unquote(encoded_version)
    if decoded_version != version or not _ALLOWED_VERSION.fullmatch(version):
        return None
    name = unquote(encoded_name)
    kind = kind.lower()
    if kind == "pypi":
        if not _PYPI.fullmatch(name):
            return None
        return ("PyPI", re.sub(r"[-_.]+", "-", name.lower()), version)
    if kind == "npm":
        if not _NPM.fullmatch(name):
            return None
        return ("npm", name, version)
    # Distro package, Maven, Go etc. are deliberately unsupported, not
    # matched to similarly named upstream packages.
    return None


def _components(document: dict) -> tuple[str, list]:
    if document.get("bomFormat") == "CycloneDX":
        if document.get("specVersion") not in {"1.5", "1.6"}:
            raise SBOMError("Unsupported CycloneDX version")
        components = document.get("components")
        format_name = "CycloneDX"
    elif document.get("spdxVersion") == "SPDX-2.3":
        components = document.get("packages")
        format_name = "SPDX-2.3"
    else:
        raise SBOMError("Unsupported SBOM format or schema version")
    if not isinstance(components, list) or len(components) > MAX_COMPONENTS:
        raise SBOMError("SBOM components missing or over limit")
    return format_name, components


def inspect_sbom(path: str | Path, *, include_identities: bool = False) -> dict:
    """Offline, bounded inventory; no provider calls or vulnerability labels."""
    document = _load_file(path)
    format_name, components = _components(document)
    identities: set[tuple[str, str, str]] = set()
    unresolved = 0
    for component in components:
        if not isinstance(component, dict):
            raise SBOMError("Invalid SBOM component")
        _safe_label(component.get("name"), max_chars=MAX_NAME_CHARS)
        version_field = "version" if format_name == "CycloneDX" else "versionInfo"
        version = component.get(version_field)
        if version is not None:
            _safe_label(version, max_chars=MAX_VERSION_CHARS)
        if format_name == "CycloneDX":
            purl = component.get("purl")
        else:
            refs = component.get("externalRefs", [])
            if not isinstance(refs, list) or len(refs) > 20:
                raise SBOMError("Invalid package reference collection")
            urls = []
            for ref in refs:
                if not isinstance(ref, dict):
                    raise SBOMError("Invalid external reference")
                if ref.get("referenceType") == "purl":
                    urls.append(ref.get("referenceLocator"))
            if len(urls) > 1:
                raise SBOMError("Ambiguous duplicate SPDX package URLs")
            purl = urls[0] if urls else None
        key = _exact_package_url(purl, version=version) if isinstance(version, str) else None
        if key is None:
            unresolved += 1
            continue
        if key in identities:
            raise SBOMError("Duplicate exact SBOM package identity")
        identities.add(key)
    sorted_ids = sorted(identities)
    counts = dict(sorted(Counter(ecosystem for ecosystem, _, _ in sorted_ids).items()))
    return {
        "schema": "penx-sbom-inventory-v1",
        "status": "inventory-only-no-advisory-check",
        "source_format": format_name,
        "total_components": len(components),
        "exact_package_identities": len(sorted_ids),
        "unresolved_components": unresolved,
        "ecosystems": counts,
        "identities": [
            {"ecosystem": ecosystem, "name": name, "version": version}
            for ecosystem, name, version in sorted_ids
        ] if include_identities else None,
        "identities_redacted": not include_identities,
        "vulnerability_verified": False,
        "network_access": False,
        "note": "No advisory comparison, distro backport validation, or exploitability claim.",
    }
