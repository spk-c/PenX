"""PX-304 offline OSV *exact listed versions* cross-check for local SBOMs.

Only compares user-supplied SBOM purl identities against explicitly
enumerated OSV affected[].versions in a user-supplied bounded local JSON
snapshot. Does NOT evaluate version ranges, VEX, distro backports, source
authenticity, advisory freshness or exploitability. Zero candidates is
never proof that a package or host is safe.
"""
from __future__ import annotations

import re
from pathlib import Path

from penx_app.intelligence.sbom_inventory import (
    SBOMError, _load_file, _ALLOWED_VERSION, _PYPI, _NPM, inspect_sbom,
)

SCHEMA = "penx-osv-exact-offline-candidates-v1"
MAX_ADVISORIES = 500
MAX_AFFECTED_PER_ADVISORY = 50
MAX_VERSIONS_PER_AFFECTED = 1000
MAX_TOTAL_VERSION_VALUES = 20_000
MAX_CANDIDATES = 2000
_OSV_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{2,127}\Z")


def _osv_name(package: object) -> tuple[str, str] | None:
    if not isinstance(package, dict):
        raise SBOMError("Invalid OSV package record")
    ecosystem = package.get("ecosystem")
    name = package.get("name")
    if not isinstance(name, str) or len(name) > 160:
        raise SBOMError("Invalid OSV package name")
    if ecosystem == "PyPI" and _PYPI.fullmatch(name):
        return "PyPI", re.sub(r"[-_.]+", "-", name.lower())
    if ecosystem == "npm" and _NPM.fullmatch(name):
        return "npm", name
    # Distro/source packages, vendor forks and ambiguous ecosystems are not
    # assumed to be equivalent to matching upstream PyPI/npm strings.
    return None


def compare_local_osv_snapshot(
    sbom_file: str | Path, osv_snapshot_file: str | Path,
    *, include_candidates: bool = False,
) -> dict:
    """Read only two local files with strict bounded JSON and no HTTP calls."""
    sbom = inspect_sbom(sbom_file, include_identities=True)
    installed = {
        (item["ecosystem"], item["name"], item["version"])
        for item in sbom["identities"]
    }
    snapshot = _load_file(osv_snapshot_file)
    # This is an explicitly prepared local collection of full OSV detail
    # objects. Query IDs alone or summary-only API responses are not enough.
    if set(snapshot) != {"vulns"} or not isinstance(snapshot["vulns"], list):
        raise SBOMError("Expected a local OSV vulnerability detail collection")
    vulns = snapshot["vulns"]
    if len(vulns) > MAX_ADVISORIES:
        raise SBOMError("Too many OSV advisory records")
    seen_ids: set[str] = set()
    candidates: set[tuple[str, str, str, str]] = set()
    unsupported_affected = 0
    ranged_affected = 0
    version_checks = 0
    advisory_records_without_affected = 0
    for record in vulns:
        if not isinstance(record, dict):
            raise SBOMError("Invalid OSV advisory record")
        identifier = record.get("id")
        if not isinstance(identifier, str) or not _OSV_ID.fullmatch(identifier):
            raise SBOMError("Invalid OSV advisory identifier")
        canonical = identifier.casefold()
        if canonical in seen_ids:
            raise SBOMError("Duplicate OSV advisory identifier")
        seen_ids.add(canonical)
        affected = record.get("affected")
        if not isinstance(affected, list) or len(affected) > MAX_AFFECTED_PER_ADVISORY:
            raise SBOMError("Invalid OSV affected collection")
        if not affected:
            advisory_records_without_affected += 1
        for entry in affected:
            if not isinstance(entry, dict):
                raise SBOMError("Invalid OSV affected entry")
            package = _osv_name(entry.get("package"))
            ranges = entry.get("ranges", [])
            if not isinstance(ranges, list) or len(ranges) > 50:
                raise SBOMError("Invalid OSV version ranges")
            if ranges:
                # Never silently convert a range to a safe/exposure verdict.
                ranged_affected += 1
            versions = entry.get("versions", [])
            if not isinstance(versions, list) or len(versions) > MAX_VERSIONS_PER_AFFECTED:
                raise SBOMError("Invalid OSV exact affected versions")
            version_checks += len(versions)
            if version_checks > MAX_TOTAL_VERSION_VALUES:
                raise SBOMError("OSV exact version budget exceeded")
            if package is None or not versions:
                unsupported_affected += 1
                continue
            ecosystem, name = package
            for version in versions:
                if (not isinstance(version, str)
                        or _ALLOWED_VERSION.fullmatch(version) is None):
                    raise SBOMError("Invalid OSV exact affected version")
                if (ecosystem, name, version) in installed:
                    candidates.add((identifier, ecosystem, name, version))
                    if len(candidates) > MAX_CANDIDATES:
                        raise SBOMError("Too many exact local OSV candidates")
    ordered = sorted(candidates)
    return {
        "schema": SCHEMA,
        "status": "offline-exact-affected-version-candidates-only",
        "sbom_components": sbom["total_components"],
        "sbom_exact_identities": sbom["exact_package_identities"],
        "sbom_unresolved_components": sbom["unresolved_components"],
        "local_advisory_records": len(vulns),
        "matched_advisory_package_pairs": len(ordered),
        "unsupported_or_unversioned_affected_entries": unsupported_affected,
        "uninterpreted_range_entries": ranged_affected,
        "advisory_records_without_affected": advisory_records_without_affected,
        "candidates_redacted": not include_candidates,
        "candidates": [
            {"advisory_id": adv, "ecosystem": ecosystem,
             "name": name, "version": version}
            for adv, ecosystem, name, version in ordered
        ] if include_candidates else None,
        "snapshot_origin_authenticated": False,
        "advisory_freshness_verified": False,
        "affected_ranges_evaluated": False,
        "vendor_backports_evaluated": False,
        "vulnerability_verified": False,
        "no_match_implies_safe": False,
        "network_access": False,
        "note": (
            "Exact locally enumerated version candidates only. Missing IDs, "
            "versions, OSV ranges, provider coverage and distro backports "
            "are unresolved, never evidence of security or exploitability."
        ),
    }
