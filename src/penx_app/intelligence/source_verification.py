"""NVD and CISA references for AI CVE claims.

CVE existence and KEV membership do not establish that a target is vulnerable.
"""
from __future__ import annotations

import re
from collections.abc import Callable
import requests

CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,8}\b", re.IGNORECASE)
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_PAGE = "https://nvd.nist.gov/vuln/detail/"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CISA_PAGE = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
MAX_LOOKUPS = 20
_nvd_cache: dict[str, str] = {}
_kev_cache: set[str] | None = None

def evidence_in_scan(quote: str, raw_scan: str) -> bool:
    """Match genuine scanner quotations, allowing a model-added source label.

    A report can say 'WhatWeb output: "MetaGenerator[...]"', while the scanner
    itself only prints 'MetaGenerator[...]'. Every substantial quoted fragment
    must appear verbatim (apart from whitespace/case) in the original scan;
    accepting only the first quote would let mixed fabricated claims through.
    Free-form paraphrases or search results are *not* accepted as scan proof.
    """
    evidence = " ".join(str(quote).split()).casefold()
    scan = " ".join(str(raw_scan).split()).casefold()
    if not evidence or len(evidence) < 12 or not scan:
        return False
    if evidence in scan:
        return True

    # Strip only a known, non-evidentiary attribution prefix.
    # Never strip an arbitrary lead-in or use a fuzzy substring score.
    without_label = re.sub(
        r"^(?:(?:whatweb|nmap|whois|dig|dns|http headers?|curl|"
        r"scanner|txt records?|mx records?)\s*(?:output|records?)?\s*:\s*)",
        "", evidence, count=1,
    ).strip()
    if without_label != evidence and len(without_label) >= 12 and without_label in scan:
        return True

    # Treat *all* quoted claims as conjunctive evidence requirements.
    # A WhatWeb quote plus an invented vulnerability advisory must fail.
    quoted = re.findall(r'["“]([^"”]+)["”]', str(quote))
    fragments = [" ".join(part.split()).casefold() for part in quoted]
    return bool(fragments) and all(len(part) >= 12 and part in scan for part in fragments)

def lookup_nvd(cve: str, api_key: str = "", *, get: Callable | None = None) -> str:
    """Returns 'listed', 'not-listed' or 'unavailable' (never a target verdict)."""
    if get is None and cve in _nvd_cache:
        return _nvd_cache[cve]
    headers = {"User-Agent": "PenX/SourceVerification"}
    if api_key:
        headers["apiKey"] = api_key
    try:
        res = (requests.get if get is None else get)(NVD_API, params={"cveId": cve}, headers=headers,
                           timeout=(3, 7), allow_redirects=False)
        res.raise_for_status()
        records = res.json().get("vulnerabilities", [])
        status = ("listed" if any(
            str(v.get("cve", {}).get("id", "")).upper() == cve for v in records
        ) else "not-listed")
    except (requests.RequestException, ValueError, KeyError, TypeError):
        status = "unavailable"
    if get is None and status != "unavailable":
        _nvd_cache[cve] = status
    return status

def verify_nvd_applicability(cve_id: str, raw_scan: str, *, api_key: str = "",
                             get: Callable | None = None) -> str:
    """Compare observed Nmap CPE/version to NVD configurations, never infer a host match.

    No CPE/version observation means UNKNOWN even when NVD lists the CVE.
    """
    from penx_app.intelligence.cve_observations import parse_nmap_services
    from penx_app.intelligence.cve_engine import applicability
    products = parse_nmap_services(raw_scan)
    if not products:
        return "unknown (no versioned Nmap CPE observed)"
    headers = {"User-Agent": "PenX/SourceVerification"}
    if api_key:
        headers["apiKey"] = api_key
    try:
        response = (requests.get if get is None else get)(NVD_API, params={"cveId": cve_id}, headers=headers,
                                timeout=(3, 7), allow_redirects=False)
        response.raise_for_status()
        entries = response.json().get("vulnerabilities", [])
        matching = [x["cve"] for x in entries if
                    isinstance(x, dict) and isinstance(x.get("cve"), dict) and
                    str(x["cve"].get("id", "")).upper() == cve_id.upper()]
        if not matching:
            return "unavailable or not listed"
        status = [applicability(matching[0], product) for product in products]
        if "version-match-needs-vendor-review" in status:
            return "version-match-needs-vendor-review (not exploit confirmation)"
        if "conditional-platform-match" in status:
            return "conditional-platform-match (additional inventory required)"
        if all(item == "no-match" for item in status):
            return "no-match for observed versioned CPEs (other products not assessed)"
        return "unknown (version/configuration uncertain)"
    except (requests.RequestException, ValueError, TypeError, KeyError):
        return "unavailable"


def load_cisa_kev(*, get: Callable | None = None) -> set[str] | None:
    """CISA catalog lookup; None means network/source unavailable."""
    global _kev_cache
    if get is None and _kev_cache is not None:
        return _kev_cache
    try:
        res = (requests.get if get is None else get)(CISA_KEV_URL, headers={"User-Agent": "PenX/SourceVerification"},
                           timeout=(3, 8), allow_redirects=False)
        res.raise_for_status()
        entries = res.json().get("vulnerabilities", [])
        if not isinstance(entries, list):
            return None
        result = {
            str(v["cveID"]).upper() for v in entries
            if isinstance(v, dict) and CVE_PATTERN.fullmatch(str(v.get("cveID", "")).upper())
        }
        if get is None:
            _kev_cache = result
        return result
    except (requests.RequestException, ValueError, TypeError, KeyError):
        return None

def verify_findings(findings: list[dict], raw_scan: str, *,
                    enabled: bool = True, nvd_api_key: str = "", max_lookups: int = MAX_LOOKUPS,
                    nvd_lookup: Callable | None = None,
                    applicability_lookup: Callable | None = None,
                    kev_loader: Callable | None = None) -> list[dict]:
    """Annotate the findings and descriptions with explicit source-check results.

    Outbound requests disclose public CVE identifiers, never the scan target or
    raw scanner results. No CVE existence check proves product/version impact.
    """
    if not enabled:
        return findings
    # Dependency overrides never share the process-global network caches.
    # They permit deterministic offline verification without monkey-patching.
    lookup = lookup_nvd if nvd_lookup is None else nvd_lookup
    check_applicability = (verify_nvd_applicability if applicability_lookup is None
                           else applicability_lookup)
    load_kev = load_cisa_kev if kev_loader is None else kev_loader
    max_lookups = max(1, min(int(max_lookups), 30))
    seen: set[str] = set()
    for finding in findings:
        matched = evidence_in_scan(finding.get("evidence", ""), raw_scan)
        blob = " ".join(str(finding.get(key, "")) for key in
                        ("vuln_name", "description", "evidence", "cve_ids"))
        cves = list(dict.fromkeys(c.upper() for c in CVE_PATTERN.findall(blob)))
        to_check = []
        for cve in cves:
            if cve in seen or len(seen) < max_lookups:
                seen.add(cve)
                to_check.append(cve)
        if not matched and finding.get("confidence") == "confirmed":
            finding["confidence"] = "possible"
        lines = [
            "Reference checks (NOT confirmation of affected software/exploitability):",
            "Scanner evidence: " + (
                "supporting text found in original scan output" if matched
                else "NOT confirmed in original scan"
            ),
        ]
        for cve in to_check:
            lines.append(f"{cve}: NVD {lookup(cve, api_key=nvd_api_key)} "
                         f"({NVD_PAGE}{cve})")
            lines.append(f"{cve}: observed-version applicability: "
                         f"{check_applicability(cve, raw_scan, api_key=nvd_api_key)}")
        if len(to_check) < len(cves):
            lines.append(f"Additional CVEs skipped: {max_lookups} unique IDs maximum per assessment.")
        finding["_checked_cves"] = to_check
        finding["source_checks"] = lines
    if seen:
        kev = load_kev()
        for finding in findings:
            for cve in finding.get("_checked_cves", []):
                status = "unavailable" if kev is None else ("listed" if cve in kev else "not-listed")
                finding["source_checks"].append(
                    f"{cve}: CISA KEV {status} ({CISA_PAGE})"
                )
    for finding in findings:
        finding.pop("_checked_cves", None)
        finding["description"] = (
            str(finding.get("description", "")).rstrip()
            + "\n\n" + "\n".join(finding["source_checks"])
        ).strip()
    return findings
