"""Bounded advisory lookup for clearly identified WordPress plugins in WhatWeb output.

Neither a public fingerprint nor a version match proves exploitable software.
No target hostname, scan output, or credential is sent to advisory services.
"""
from __future__ import annotations

import re
import requests
from packaging.version import Version, InvalidVersion

SUPPORTED = {"elementor": "elementor", "flyingpress": "flyingpress"}
PATTERN = re.compile(r"\b(?:MetaGenerator\[Elementor\s+([0-9][A-Za-z0-9._-]*)|PoweredBy\[FlyingPress\])", re.I)
GH_API = "https://api.github.com/advisories"


def observed_plugins(raw_scan: str) -> list[dict]:
    plugins = {}
    for match in PATTERN.finditer(raw_scan or ""):
        key = "elementor" if match.group(1) else "flyingpress"
        version = match.group(1) or ""
        if not version and key == "elementor":
            continue
        plugins[key] = {"slug": SUPPORTED[key], "version": version,
                        "evidence": match.group(0)}
    return list(plugins.values())


def _affected(version: str, vulnerable_ranges: list) -> str:
    if not version:
        return "version-unknown"
    try:
        current = Version(version)
    except InvalidVersion:
        return "version-uncertain"
    # GitHub semver ranges are not directly equivalent to Python packaging.
    # Avoid evaluating ecosystem-specific expressions as if they were universal.
    return "version-range-requires-vendor-review"


def research_plugins(raw_scan: str, *, token: str = "", enabled: bool = True,
                     limit: int = 10, http_get=None) -> dict:
    """Query only fixed GitHub Advisory endpoints with an optional test transport.

    The injected client is call-local; there is no shared response cache.
    Neither the raw scanner text nor the assessed target is sent upstream.
    """
    plugins = observed_plugins(raw_scan)
    checks = []
    candidates = []
    if not enabled:
        return {"observations": plugins, "checks": [{"service": "GitHub Advisory", "status": "disabled"}], "candidates": []}
    if not plugins:
        return {"observations": [], "checks": [{"service": "GitHub Advisory", "status": "skipped", "reason": "No supported WhatWeb plugin fingerprint"}], "candidates": []}
    fetch = requests.get if http_get is None else http_get
    bounded_limit = max(1, min(limit, 20))
    for plugin in plugins:
        # GitHub's reviewed advisory endpoint is searched by the exact package
        # identifier. This mapping is deliberately restricted to known WordPress
        # slugs to avoid broad product-name collisions.
        params = {"ecosystem": "composer", "affects": "wpackagist-plugin/" + plugin["slug"],
                  "type": "reviewed", "per_page": bounded_limit}
        headers = {"Accept": "application/vnd.github+json",
                   "X-GitHub-Api-Version": "2022-11-28",
                   "User-Agent": "PenX-WordPress-Advisory/1.0"}
        if token:
            headers["Authorization"] = "Bearer " + token
        response = None
        try:
            response = fetch(GH_API, params=params, headers=headers,
                             timeout=(5, 15), allow_redirects=False)
            response.raise_for_status()
            advisories = response.json()
            if not isinstance(advisories, list):
                raise ValueError("Unexpected advisory payload")
            checks.append({"service": "GitHub Advisory", "package": plugin["slug"],
                           "status": "queried", "results": len(advisories)})
            for advisory in advisories[:bounded_limit]:
                if not isinstance(advisory, dict):
                    continue
                url = str(advisory.get("html_url") or "")
                if not url.startswith("https://github.com/advisories/"):
                    continue
                identifier = advisory.get("cve_id") or advisory.get("ghsa_id")
                if not identifier:
                    continue
                candidates.append({"id": identifier, "source": "GitHub Advisory",
                                   "status": _affected(plugin["version"], advisory.get("vulnerabilities", [])),
                                   "product": plugin["slug"], "version": plugin["version"] or "unknown",
                                   "url": url, "evidence": plugin["evidence"],
                                   "vendor_advisories": []})
        except requests.HTTPError as exc:
            status = getattr(exc.response, "status_code", None)
            checks.append({"service": "GitHub Advisory", "package": plugin["slug"],
                           "status": "unavailable",
                           "reason": ("HTTP " + str(status)) if status is not None
                           else "Request failed"})
        except (requests.RequestException, ValueError, TypeError):
            checks.append({"service": "GitHub Advisory", "package": plugin["slug"],
                           "status": "unavailable", "reason": "Request failed or response invalid"})
        finally:
            # Requests does not automatically release a response just because
            # JSON parsing or HTTP-status validation fails.
            if response is not None:
                response.close()
    return {"observations": plugins, "checks": checks, "candidates": candidates}


def format_plugin_report(report: dict, *, nvd_key_configured: bool = False,
                         github_key_configured: bool = False) -> str:
    lines = ["ADVISORY LOOKUP DIAGNOSTICS (candidate research; no target verification):",
             "NVD API key: " + ("configured" if nvd_key_configured else "absent"),
             "GitHub Advisory token: " + ("configured" if github_key_configured else "absent")]
    for plugin in report["observations"]:
        lines.append("WhatWeb plugin: " + plugin["slug"] + " version " +
                     (plugin["version"] or "unknown") + " (" + plugin["evidence"] + ")")
    for check in report["checks"]:
        lines.append("GitHub Advisory " + check["status"] + ": " + check.get("package", "") +
                     (" (" + check.get("reason", "") + ")" if check.get("reason") else "") +
                     ("; matches=" + str(check["results"]) if "results" in check else ""))
    for candidate in report["candidates"]:
        lines.append("ADVISORY LEAD: " + candidate["id"] + " | " + candidate["product"] +
                     " " + candidate["version"] + " | " + candidate["status"] + " | " + candidate["url"])
    lines.append("NVD WordPress fingerprint lookup: skipped (no verified CPE mapping from WhatWeb).")
    lines.append("Note: WordPress advisory coverage can be incomplete. Empty search results do not prove safety.")
    return "\n".join(lines)
