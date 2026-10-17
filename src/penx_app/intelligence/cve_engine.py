"""Version-aware CVE candidate discovery from observed CPEs and package URLs.

No network scans are performed here. Queries contain CPE or package/version,
not IP addresses, targets, raw HTTP responses or credentials. Results are
research candidates, never proof of target exploitability.
"""
from __future__ import annotations

from functools import lru_cache
from collections.abc import Callable
from penx_app.intelligence.nvd_disk_cache import load as load_nvd_cache, store as store_nvd_cache

import time
import re
from urllib.parse import quote, urlsplit

import requests
from packaging.version import InvalidVersion, Version
from penx_app.intelligence.cve_priority import extract_cvss, enrich_priority
from penx_app.intelligence.vendor_status import vendor_guidance
from penx_app.intelligence.package_inventory import load_inventory, InventoryError

from penx_app.intelligence.cve_observations import Product, Package, cpe_components, parse_nmap_services, parse_explicit_packages, github_ecosystem

NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV = "https://api.osv.dev/v1/query"
GH = "https://api.github.com/advisories"
USER_AGENT = {"User-Agent": "PenX-CVE-Discovery/0.1 (authorized research)"}
MAX_PAGES = 2
PAGE_SIZE = 50
MAX_RESULTS = 15
CVE_ID = re.compile(r"CVE-\d{4}-\d{4,8}\Z", re.ASCII | re.IGNORECASE)
OSV_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{2,127}\Z", re.ASCII)

def compare_versions(one: str, two: str) -> int | None:
    """Return strict ordering; unknown/vendor-specific version syntax is uncertain."""
    try:
        a, b = Version(one), Version(two)
    except (InvalidVersion, TypeError, ValueError):
        return None
    return (a > b) - (a < b)

def version_applies(version: str, match: dict, criteria_version: str) -> bool | None:
    """True/False/None (cannot compare). Version strings are not guessed."""
    if not version or version in ("*", "-"):
        return None
    bounds = (
        ("versionStartIncluding", True, True),
        ("versionStartExcluding", True, False),
        ("versionEndIncluding", False, True),
        ("versionEndExcluding", False, False),
    )
    if not any(match.get(key) for key, *_ in bounds):
        if criteria_version in ("*", "-", ""):
            return True
        return version.lower() == criteria_version.lower()
    for key, is_start, inclusive in bounds:
        bound = match.get(key)
        if not bound:
            continue
        result = compare_versions(version, bound)
        if result is None:
            return None
        if is_start and (result < 0 or (result == 0 and not inclusive)):
            return False
        if not is_start and (result > 0 or (result == 0 and not inclusive)):
            return False
    return True

def _candidate_match(match: dict, product: Product) -> bool | None:
    if match.get("vulnerable") is not True:
        return False
    target = cpe_components(product.cpe)
    rule = cpe_components(match.get("criteria", ""))
    if not target or not rule:
        return None
    if any(r not in ("*", t) for r, t in zip(rule[:3], target[:3])):
        return False
    return version_applies(target[3], match, rule[3])

def applicability(cve: dict, product: Product) -> str:
    """Evaluate NVD AND/OR/negation with three-valued logic.

    One scanned service does not constitute a complete host inventory.
    Conditions about other products/OSes are UNKNOWN, never assumed true.
    """
    configs = cve.get("configurations") or []
    if not isinstance(configs, list) or not configs:
        return "unresolved"
    target = cpe_components(product.cpe)
    observed = False
    complex_expression = False
    unknown_version = False

    def evaluate_leaf(item):
        nonlocal observed, unknown_version
        if not isinstance(item, dict):
            return None
        criteria_text = item.get("criteria", "")
        if not isinstance(criteria_text, str):
            return None
        criteria = cpe_components(criteria_text)
        if not target or not criteria:
            return None
        if any(expected not in ("*", actual) for expected, actual in zip(criteria[:3], target[:3])):
            # The inventory only describes this service, not all installed software.
            return None
        observed = True
        if item.get("vulnerable") is False:
            return None
        result = version_applies(target[3], item, criteria[3])
        if result is None:
            unknown_version = True
        return result

    def combine(values, operator):
        if not values:
            return None
        if operator == "AND":
            if False in values:
                return False
            return True if all(v is True for v in values) else None
        if True in values:
            return True
        return False if all(v is False for v in values) else None

    def evaluate_node(node):
        nonlocal complex_expression
        if not isinstance(node, dict):
            return None
        op = node.get("operator", "OR")
        if not isinstance(op, str) or op not in ("AND", "OR"):
            return None
        if op == "AND" or node.get("negate"):
            complex_expression = True
        leaves = node.get("cpeMatch") or []
        children = node.get("children") or []
        if not isinstance(leaves, list) or not isinstance(children, list):
            return None
        values = [evaluate_leaf(x) for x in leaves if isinstance(x, dict)]
        values += [evaluate_node(x) for x in children if isinstance(x, dict)]
        value = combine(values, op)
        if node.get("negate"):
            # Negation without full asset inventory cannot produce a confirmed match.
            return None
        return value

    values: list[bool | None] = []
    for cfg in configs:
        if not isinstance(cfg, dict):
            continue
        op = cfg.get("operator", "OR")
        if not isinstance(op, str) or op not in ("AND", "OR"):
            values.append(None)
            continue
        if op == "AND":
            complex_expression = True
        nodes = cfg.get("nodes") or []
        if not isinstance(nodes, list):
            values.append(None)
            continue
        values.append(combine([evaluate_node(n) for n in nodes], op))
    if not observed:
        return "no-match"
    overall = combine(values, "OR")
    if overall is True:
        return "conditional-platform-match" if complex_expression else "version-match-needs-vendor-review"
    if overall is False:
        return "no-match"
    if unknown_version:
        return "version-or-configuration-uncertain"
    return "conditional-platform-match" if complex_expression else "version-or-configuration-uncertain"

def _get(url: str, *, params: dict, headers: dict, timeout: int = 9,
         http_get: Callable | None = None) -> dict | list:
    """Bounded catalogue HTTP GET with optional call-local transport."""
    client = requests.get if http_get is None else http_get
    response = client(url, params=params, headers=headers,
                      timeout=(3, timeout), allow_redirects=False)
    if response.status_code == 429:
        # Close the throttled response before backing off and issuing the
        # single bounded retry, including when the delay is malformed.
        try:
            retry_after = response.headers.get("Retry-After", "1")
        finally:
            response.close()
        try:
            time.sleep(min(max(float(retry_after), 0), 1))
        except ValueError:
            time.sleep(1)
        response = client(url, params=params, headers=headers,
                          timeout=(3, timeout), allow_redirects=False)
    try:
        response.raise_for_status()
        return response.json()
    finally:
        response.close()

def _fetch_nvd(cpe: str, api_key: str, *,
               http_get: Callable | None = None) -> tuple[dict, ...]:
    """Get NVD catalogue data; called only when a valid cache is unavailable."""
    headers = dict(USER_AGENT)
    if api_key:
        headers["apiKey"] = api_key
    results: list[dict] = []
    for page in range(MAX_PAGES):
        data = _get(NVD, params={"cpeName": cpe, "resultsPerPage": PAGE_SIZE,
                                 "startIndex": page * PAGE_SIZE}, headers=headers,
                    http_get=http_get)
        if not isinstance(data, dict):
            raise ValueError("Invalid NVD response shape")
        items = data.get("vulnerabilities", [])
        if not isinstance(items, list):
            break
        results.extend(items[:PAGE_SIZE])
        if len(results) >= min(int(data.get("totalResults", 0)), MAX_PAGES * PAGE_SIZE):
            break
        if len(items) < PAGE_SIZE:
            break
    return tuple(results)


@lru_cache(maxsize=64)
def _memory_nvd(cpe: str, api_key: str) -> tuple[dict, ...]:
    """Existing in-memory cache when persistent caching is disabled."""
    return _fetch_nvd(cpe, api_key)


def _cached_nvd(cpe: str, api_key: str) -> tuple[dict, ...]:
    """Use only fresh disk entries and bypass permanent memory caching when enabled."""
    from penx_app.intelligence.nvd_disk_cache import enabled as disk_cache_enabled
    if not disk_cache_enabled():
        return _memory_nvd(cpe, api_key)
    cached = load_nvd_cache(cpe)
    if cached is not None:
        return cached
    result = _fetch_nvd(cpe, api_key)
    store_nvd_cache(cpe, result)
    return result


# Keep existing test/caller cache reset API for the disabled-memory-cache path.
setattr(_cached_nvd, "cache_clear", _memory_nvd.cache_clear)

def _vendor_refs(cve: dict) -> list[str]:
    """Retain valid HTTPS vendor links despite malformed provider siblings."""
    links: list[str] = []
    rows = cve.get("references", []) or []
    if not isinstance(rows, list):
        return links
    for item in rows[:100]:
        if not isinstance(item, dict):
            continue
        tags = item.get("tags", [])
        if not isinstance(tags, list):
            continue
        if "Vendor Advisory" not in tags and "Patch" not in tags:
            continue
        url = item.get("url", "")
        if (not isinstance(url, str) or len(url) > 2048
                or any(char.isspace() or ord(char) < 32 for char in url)):
            continue
        try:
            parsed = urlsplit(url)
            if (parsed.scheme == "https" and parsed.hostname
                    and not parsed.username and not parsed.password
                    and parsed.port != 0):
                links.append(url)
        except ValueError:
            # Invalid IPv6 brackets or ports must not discard the CVE itself.
            continue
        if len(links) >= 2:
            break
    return links

def nvd_candidates(product: Product, *, api_key: str = "",
                   limit: int = MAX_RESULTS,
                   http_get: Callable | None = None) -> tuple[list[dict], str]:
    try:
        # Injected clients bypass production memory and disk caches.
        results = (_cached_nvd(product.cpe, api_key) if http_get is None
                   else _fetch_nvd(product.cpe, api_key, http_get=http_get))
    except (requests.RequestException, ValueError, KeyError, TypeError):
        return [], "NVD unavailable for " + product.cpe
    candidates = []
    malformed = False
    for item in results:
        if not isinstance(item, dict) or not isinstance(item.get("cve"), dict):
            malformed = True
            continue
        cve = item["cve"]
        identifier = cve.get("id", "")
        if not isinstance(identifier, str) or not CVE_ID.fullmatch(identifier):
            malformed = True
            continue
        if str(cve.get("vulnStatus") or "").casefold() == "rejected":
            continue
        # An invalid whole references container makes this provider record
        # untrustworthy; only individual malformed links are tolerated.
        if (cve.get("references") is not None
                and not isinstance(cve["references"], list)):
            malformed = True
            continue
        identifier = identifier.upper()
        try:
            state = applicability(cve, product)
            # Malformed provider versions/bounds must not terminate research.
            refs = _vendor_refs(cve)
            metrics = extract_cvss(cve.get("metrics", {}))
        except (AttributeError, TypeError, ValueError, IndexError):
            malformed = True
            continue
        if state == "no-match":
            continue
        candidates.append({
            "id": identifier, "source": "NVD", "status": state,
            "product": product.label, "version": product.version,
            "port": product.port, "evidence": product.evidence,
            "url": "https://nvd.nist.gov/vuln/detail/" + identifier,
            "vendor_advisories": refs,
            **metrics,
        })
        if len(candidates) >= limit:
            break
    return candidates, ("NVD returned malformed candidate records" if malformed else "")

def osv_candidates(package: Package, *, limit: int = MAX_RESULTS,
                   http_post: Callable | None = None) -> tuple[list[dict], str]:
    results: list[dict] = []
    post = requests.post if http_post is None else http_post
    token = ""
    malformed_ids = False
    try:
        for _ in range(MAX_PAGES):
            payload: dict[str, object] = {"package": {"purl": package.purl}}
            if token:
                payload["page_token"] = token
            response = post(OSV, json=payload, headers=USER_AGENT,
                            timeout=(3, 9), allow_redirects=False)
            try:
                response.raise_for_status()
                obj = response.json()
            finally:
                response.close()
            if not isinstance(obj, dict) or not isinstance(obj.get("vulns", []), list):
                return results, "OSV returned an invalid response shape for " + package.purl
            for vuln in obj.get("vulns", []):
                if not isinstance(vuln, dict):
                    return results, "OSV returned a malformed vulnerability for " + package.purl
                # Do not coerce arbitrary provider objects into official
                # looking identifiers or URLs. OSV uses ASCII identifiers
                # such as GHSA-, PYSEC-, RUSTSEC-, GO- and CVE-.
                identifier = vuln.get("id")
                if (not isinstance(identifier, str)
                        or not OSV_ID.fullmatch(identifier)):
                    malformed_ids = True
                    continue
                results.append({
                    "id": identifier, "source": "OSV", "status": "package-version-matched",
                    "product": package.name, "version": package.version,
                    "port": "", "evidence": package.purl,
                    "url": "https://osv.dev/vulnerability/" + quote(identifier, safe=""),
                    "vendor_advisories": [],
                })
                if len(results) >= limit:
                    return results, ("OSV returned malformed candidate IDs; results may be incomplete."
                                     if malformed_ids else "")
            next_token = obj.get("next_page_token")
            if next_token is not None and not isinstance(next_token, str):
                return results, "OSV returned a malformed pagination token for " + package.purl
            token = next_token or ""
            if not token:
                break
    except (requests.RequestException, ValueError, KeyError, TypeError):
        return results, "OSV unavailable/incomplete for " + package.purl
    return results, ("OSV returned malformed candidate IDs; results may be incomplete."
                     if malformed_ids else "")

def github_candidates(package: Package, *, token: str = "",
                      limit: int = MAX_RESULTS,
                      http_get: Callable | None = None) -> tuple[list[dict], str]:
    ecosystem = github_ecosystem(package.purl)
    if not ecosystem:
        return [], ""
    headers = {**USER_AGENT, "Accept": "application/vnd.github+json",
               "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        headers["Authorization"] = "Bearer " + token
    try:
        items = _get(GH, params={"ecosystem": ecosystem,
                                 "affects": f"{package.name}@{package.version}",
                                 "type": "reviewed", "per_page": limit},
                     headers=headers, http_get=http_get)
        if not isinstance(items, list):
            return [], "Unexpected GitHub advisory response."
        result: list[dict] = []
        for item in items[:limit]:
            if not isinstance(item, dict):
                return result, "GitHub Advisories returned malformed records for " + package.purl
            ident = item.get("cve_id") or item.get("ghsa_id")
            url = item.get("html_url", "")
            if not isinstance(ident, str) or not isinstance(url, str):
                return result, "GitHub Advisories returned malformed records for " + package.purl
            if not ident or not url.startswith("https://github.com/advisories/"):
                continue
            result.append({
                "id": ident, "source": "GitHub Advisory",
                "status": "package-version-matched",
                "product": package.name, "version": package.version,
                "port": "", "evidence": package.purl, "url": url,
                "vendor_advisories": [],
            })
        return result, ""
    except (requests.RequestException, ValueError, KeyError, TypeError):
        return [], "GitHub Advisories unavailable for " + package.purl

def discover(raw_scan: str, *, enabled: bool = True,
             nvd_api_key: str = "", github_token: str = "",
             max_services: int = 3, max_packages: int = 4,
             max_results: int = MAX_RESULTS, priority: bool = True,
             distro_hint: str = "", inventory_file: str = "",
             debian_tracker_file: str = "",
             nvd_lookup: Callable | None = None,
             osv_lookup: Callable | None = None,
             github_lookup: Callable | None = None,
             priority_lookup: Callable | None = None,
             vendor_lookup: Callable | None = None) -> dict:
    """Run limited, version-specific catalogue searches; never scan a host."""
    if not enabled:
        return {"observations": [], "candidates": [], "warnings": []}
    max_services = max(0, min(int(max_services), 12))
    max_packages = max(0, min(int(max_packages), 12))
    max_results = max(1, min(int(max_results), 50))
    products = parse_nmap_services(raw_scan, max_services=max_services) if max_services else []
    packages = parse_explicit_packages(raw_scan, max_packages=max_packages) if max_packages else []
    candidates: list[dict] = []
    warnings: list[str] = []
    inventory = {}
    if inventory_file:
        try:
            inventory = load_inventory(inventory_file)
            if distro_hint:
                hint_distro, _, hint_release = distro_hint.partition(":")
                if (hint_distro, hint_release) != (inventory["distro"], inventory["release"]):
                    warnings.append("Configured distro hint conflicts with explicit package inventory; vendor comparisons disabled.")
                    inventory = {}
                    distro_hint = ""
        except (OSError, InventoryError, ValueError) as exc:
            warnings.append("Package inventory unavailable/invalid: " + str(exc)[:120])
    observations = [p.evidence for p in products] + [p.purl for p in packages]
    seen = set()
    def absorb(records):
        for result in records:
            key = (result["id"], result["product"], result["version"])
            if key not in seen and len(candidates) < max_results:
                seen.add(key)
                candidates.append(result)
    # Scoped research ports preserve legacy defaults for production callers.
    nvd_client = nvd_candidates if nvd_lookup is None else nvd_lookup
    osv_client = osv_candidates if osv_lookup is None else osv_lookup
    github_client = github_candidates if github_lookup is None else github_lookup
    priority_client = enrich_priority if priority_lookup is None else priority_lookup
    vendor_client = vendor_guidance if vendor_lookup is None else vendor_lookup
    for prod in products:
        hits, warn = nvd_client(prod, api_key=nvd_api_key, limit=max_results)
        absorb(hits)
        if warn:
            warnings.append(warn)
    for pkg in packages:
        hits, warn = osv_client(pkg, limit=max_results)
        absorb(hits)
        if warn:
            warnings.append(warn)
        hits, warn = github_client(pkg, token=github_token, limit=max_results)
        absorb(hits)
        if warn:
            warnings.append(warn)
    if candidates and priority:
        candidates, issues = priority_client(candidates)
        warnings.extend(issues)
    if (distro_hint or inventory) and candidates:
        for candidate in candidates[:12]:
            candidate["vendor_status"] = vendor_client(
                candidate, distro_hint=distro_hint, inventory=inventory,
                debian_tracker_file=debian_tracker_file)
    return {"observations": observations, "candidates": candidates, "warnings": warnings}

def format_report(report: dict) -> str:
    """Bounded plain text for prompting and persisted report, not a model verdict."""
    if not report["observations"] and not report["candidates"] and not report["warnings"]:
        return ""
    lines = [
        "AUTOMATED CVE RESEARCH CANDIDATES (NOT confirmed target vulnerabilities):",
        "Only exact CPE/package-version identifiers were queried. Version banners and "
        "NVD matches alone do not prove target applicability; check vendor fixes, "
        "package backports and required OS/platform conditions.",
    ]
    for value in report["observations"]:
        lines.append("Observed identifier: " + value)
    for item in report["candidates"]:
        lines.append(f"CANDIDATE: {item['id']} | {item['source']} | {item['status']} | "
                     f"{item['product']} {item['version']} | {item['url']}")
        if item.get("cvss_score") is not None:
            lines.append(f"NVD CVSS {item['cvss_version']}: {item['cvss_score']} {item.get('cvss_vector','')}")
        if item.get("epss") is not None:
            lines.append(f"FIRST EPSS: {item['epss']:.5f}, percentile: {item['epss_percentile']:.5f} (date: {item.get('epss_date','')})")
        if item.get("kev_status"):
            lines.append(f"CISA KEV: {item['kev_status']} (not proof of affected target)")
        for source in item.get("vendor_status", []):
            lines.append("DISTRIBUTION ADVISORY: "
                         + str(source.get("source","")) + ": " + str(source.get("status",""))
                         + " | source package: " + str(source.get("package","unknown"))
                         + " | installed: " + str(source.get("installed_version","unknown"))
                         + " | fix version: " + str(source.get("fixed_version","unknown"))
                         + " | installed version comparison: " + str(source.get("installed_status","NOT checked"))
                         + " | " + str(source.get("url","")))
        for link in item.get("vendor_advisories", []):
            lines.append("VENDOR ADVISORY (review patch/backport applicability): " + link)
    for warning in report["warnings"]:
        lines.append("SOURCE WARNING: " + warning)
    if not report["candidates"]:
        lines.append("No version-qualified CVE candidates returned; this is NOT evidence of safety.")
    return "\n".join(lines)
