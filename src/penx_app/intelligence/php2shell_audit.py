"""Offline PHP2Shell release-posture audit from already saved scanner banners.

CVE-2026-109618 / CVE-2026-109619: version observations only.
No probing, uploads, sessions, payloads, exploitation, or network access.
A banner is NOT evidence of server-side configuration or exploitability.
"""
from __future__ import annotations

import re

from penx_app.reporting.scan_coverage import ADAPTER_STATUS, HEAD

CVE_IDS = ("CVE-2026-109618", "CVE-2026-109619")
FIXED_RELEASES = {"8.2": "8.2.35", "8.3": "8.3.36",
                  "8.4": "8.4.27", "8.5": "8.5.12"}
PHP_ADVISORY_URL = "https://www.php.net/"
_PHP_VERSION = r"([5-9]\.[0-9]{1,2}\.[0-9]{1,3})"
_POWERED = re.compile(r"\bX-Powered-By\s*[:=]\s*PHP\s*/\s*" + _PHP_VERSION + r"\b", re.I)
_WHATWEB = re.compile(r"\bPHP\[\s*v?" + _PHP_VERSION + r"\s*\]", re.I)
_SOURCE_NAMES = frozenset(("HTTP HEADERS", "WEB FINGERPRINT", "WHATWEB"))
_MAX_SCAN_CHARS = 2_000_000
_MAX_SECTION_CHARS = 150_000


def _observed_banners(raw_scan: str) -> list[dict[str, str]]:
    """Read only known scanner sections, not AI text or arbitrary log fragments."""
    if not isinstance(raw_scan, str) or len(raw_scan) > _MAX_SCAN_CHARS:
        return []
    markers = list(HEAD.finditer(raw_scan))
    observed: list[dict[str, str]] = []
    seen = set()
    for i, marker in enumerate(markers):
        source = marker.group(1).strip().upper()
        if source not in _SOURCE_NAMES:
            continue
        end = markers[i + 1].start() if i + 1 < len(markers) else len(raw_scan)
        section = raw_scan[marker.end():end][:_MAX_SECTION_CHARS]
        metadata_text = re.sub(r"^\s*={20,}\r?\n", "", section).lstrip()
        marker_status = ADAPTER_STATUS.match(metadata_text)
        if marker_status and (marker_status.group(1) == "FAILED"
                              or marker_status.group(2) == "NO"):
            continue
        for pattern in (_POWERED, _WHATWEB):
            for match in pattern.finditer(section):
                version = match.group(1)
                key = (source, version)
                if key not in seen:
                    seen.add(key)
                    observed.append({"source": source, "php_version": version})
                if len(observed) >= 16:
                    return observed
    return observed


def _classify_version(version: str) -> str:
    try:
        major, minor, patch = tuple(map(int, version.split(".")))
    except (ValueError, TypeError):
        return "unknown"
    branch = f"{major}.{minor}"
    if branch in FIXED_RELEASES:
        return ("fixed_release_observed" if
                (major, minor, patch) >= tuple(map(int, FIXED_RELEASES[branch].split(".")))
                else "pre_fix_release_observed")
    if (major == 5 and minor >= 4) or major in (7,) or (major == 8 and minor <= 1):
        return "unsupported_branch_observed"
    return "unknown"


_LIVE_POWERED = re.compile(r"^\s*PHP\s*/\s*" + _PHP_VERSION + r"\s*$", re.I)


def classify_live_php2shell_headers(values: list[str]) -> dict[str, object]:
    """Classify headers observed by a live HTTP scan, never as confirmed RCE.

    Upstream patched-looking or vendor-backported versions are not verified
    patches by a public response header alone.
    """
    versions: set[str] = set()
    invalid = False
    for value in values[:8]:
        match = _LIVE_POWERED.fullmatch(value) if isinstance(value, str) else None
        if match:
            versions.add(match.group(1))
        else:
            invalid = True
    if len(values) > 8 or len(versions) > 1 or invalid:
        status = "UNVERIFIED"
        reason = "Multiple, malformed or conflicting PHP headers."
    elif not versions:
        status = "UNVERIFIED"
        reason = "No reliable PHP version in live response headers."
    else:
        release = _classify_version(next(iter(versions)))
        status = ("POTENTIALLY_VULNERABLE"
                  if release in ("pre_fix_release_observed",
                                 "unsupported_branch_observed")
                  else "UNVERIFIED")
        reason = ("Reported pre-fix PHP release; upstream patches and vendor "
                  "backports still require verification."
                  if status == "POTENTIALLY_VULNERABLE"
                  else "Public headers do not attest installed PHP patches.")
    return {
        "status": status,
        "observed_php_versions": sorted(versions),
        "reason": reason,
        "patch_verified": False,
        "rce_confirmed": False,
        "exploit_tested": False,
    }


def _live_marker_present(raw_scan: str) -> bool:
    """Locate the marker only in a successful HTTP HEADERS scanner section."""
    if not isinstance(raw_scan, str) or len(raw_scan) > _MAX_SCAN_CHARS:
        return False
    markers = list(HEAD.finditer(raw_scan))
    for i, marker in enumerate(markers):
        if marker.group(1).strip().upper() != "HTTP HEADERS":
            continue
        end = markers[i + 1].start() if i + 1 < len(markers) else len(raw_scan)
        section = raw_scan[marker.end():end][:_MAX_SECTION_CHARS]
        section = re.sub(r"^\s*={20,}\r?\n", "", section).lstrip()
        adapter = ADAPTER_STATUS.match(section)
        if adapter and (adapter.group(1) == "FAILED" or adapter.group(2) == "NO"):
            continue
        if re.search(r"(?m)^\[PENX PHP2SHELL LIVE\] (?:POTENTIALLY_VULNERABLE|UNVERIFIED)$",
                     section):
            return True
    return False


def assess_php2shell(raw_scan: str) -> dict:
    """Deterministic, *non-exploiting* advisory; version != confirmed RCE."""
    banners = _observed_banners(raw_scan)
    classifications = {item["php_version"]: _classify_version(item["php_version"])
                       for item in banners}
    statuses = set(classifications.values())
    if not banners:
        status = "unknown"
    elif len(classifications) > 1 or len(statuses) != 1:
        status = "conflicting_or_multiple_versions"
    else:
        status = next(iter(statuses))
    verification_status = ("POTENTIALLY_VULNERABLE"
                           if status in ("pre_fix_release_observed",
                                         "unsupported_branch_observed")
                           else "UNVERIFIED")
    return {
        "name": "PHP2Shell release posture",
        "verification_status": verification_status,
        "live_header_check_observed": _live_marker_present(raw_scan),
        "patch_verified": False,
        "rce_confirmed": False,
        "cve_ids": list(CVE_IDS),
        "status": status,
        "exploit_tested": False,
        "observations": banners,
        "fixed_releases": dict(FIXED_RELEASES),
        "advisory": PHP_ADVISORY_URL,
        "recommended_action": (
            "Verify the actual PHP runtime and vendor patch status on the server. "
            "Apply the vendor security update; unsupported branches require migration."
        ),
        "limitations": (
            "Only an already collected, untrusted HTTP/WhatWeb version banner was checked. "
            "No PHP runtime configuration, actual patch level, reachability of vulnerable "
            "code, or RCE was verified. Headers may be hidden, spoofed or originate "
            "from a proxy; distributions may backport fixes. A patched-looking "
            "banner does not establish that the deployment is safe. Disabling "
            "session.upload_progress.enabled mitigates some paths but is not a "
            "complete fix for these vulnerabilities."
        ),
    }
