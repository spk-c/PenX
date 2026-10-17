"""CVE prioritization from FIRST EPSS, NVD CVSS and CISA KEV."""
import math
import re
import requests
from penx_app.intelligence.source_verification import load_cisa_kev
EPSS_URL = "https://api.first.org/data/v1/epss"
CVE = re.compile(r"^CVE-\d{4}-\d{4,8}$", re.I)

def extract_cvss(metrics):
    for field in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(field, []) if isinstance(metrics, dict) else []
        if not isinstance(entries, list):
            continue
        # NVD is untrusted input; a scalar/str entry must not abort an
        # otherwise valid CVE research report.
        for item in sorted((row for row in entries if isinstance(row, dict)),
                           key=lambda v: v.get("type") != "Primary"):
            data = item.get("cvssData") or {}
            if not isinstance(data, dict):
                continue
            score = data.get("baseScore")
            if isinstance(score, (int, float)) and not isinstance(score, bool) and math.isfinite(score) and 0 <= score <= 10:
                return {"cvss_score": float(score), "cvss_vector": data.get("vectorString", ""), "cvss_version": data.get("version", ""), "cvss_source": item.get("source", "")}
    return {}

def fetch_epss(ids, *, http_get=None):
    """Bounded FIRST lookup with an isolated, call-scoped HTTP transport."""
    ids = list(dict.fromkeys(x.upper() for x in ids
                             if isinstance(x, str) and CVE.fullmatch(x)))[:30]
    if not ids:
        return {}, ""
    try:
        get = requests.get if http_get is None else http_get
        r = get(EPSS_URL, params={"cve": ",".join(ids)}, timeout=(3, 9),
                allow_redirects=False)
        try:
            r.raise_for_status()
            payload = r.json()
        finally:
            r.close()
        if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
            raise ValueError("Malformed EPSS response")
        out = {}
        malformed = False
        for item in payload["data"]:
            if not isinstance(item, dict):
                malformed = True
                continue
            key = str(item.get("cve", "")).upper()
            if key not in ids:
                continue
            try:
                score, percentile = float(item["epss"]), float(item["percentile"])
                if all(math.isfinite(v) and 0 <= v <= 1 for v in (score, percentile)):
                    out[key] = {"epss": score, "epss_percentile": percentile, "epss_date": item.get("date", ""), "epss_url": "https://www.first.org/epss/"}
                else:
                    malformed = True
            except (KeyError, TypeError, ValueError):
                malformed = True
                continue
        return out, ("EPSS returned malformed records; scores may be incomplete."
                     if malformed else "")
    except (requests.RequestException, ValueError, TypeError, KeyError):
        return {}, "EPSS unavailable; risk score unknown."

def _safe_numeric_score(candidate: dict, field: str, ceiling: float) -> float:
    """Untrusted candidate metadata must never crash ranking or raise priority.

    Only finite numeric scores within their documented ranges contribute to
    ranking. Text, booleans, NaN, infinity and out-of-range numbers are unknown.
    """
    value = candidate.get(field)
    if (isinstance(value, (int, float)) and not isinstance(value, bool)
            and math.isfinite(value) and 0 <= value <= ceiling):
        return float(value)
    return -1.0


def enrich_priority(candidates, enabled=True, *, epss_lookup=None, kev_lookup=None):
    """Use explicit advisory clients while keeping unavailable sources unknown."""
    if not enabled:
        return candidates, []
    ids = list(dict.fromkeys(str(x.get("id", "")).upper() for x in candidates
                             if CVE.fullmatch(str(x.get("id", "")))))
    try:
        epss, error = (fetch_epss if epss_lookup is None else epss_lookup)(ids)
        if not isinstance(epss, dict) or not isinstance(error, str):
            raise ValueError("Invalid EPSS provider contract")
        valid_scores = {}
        for key, row in epss.items():
            if key not in ids:
                continue
            if not isinstance(row, dict):
                raise ValueError("Invalid EPSS record")
            score, percentile = row.get("epss"), row.get("epss_percentile")
            if (any(type(value) not in (float, int) or not math.isfinite(value)
                    or not 0 <= value <= 1 for value in (score, percentile))):
                raise ValueError("Invalid EPSS score or percentile")
            valid_scores[key] = row
        epss = valid_scores
    except (requests.RequestException, ValueError, TypeError, KeyError):
        epss, error = {}, "EPSS unavailable; risk score unknown."
    try:
        kev = ((load_cisa_kev if kev_lookup is None else kev_lookup)()
               if ids else set())
    except (requests.RequestException, ValueError, TypeError):
        kev = None
    if kev is not None and not isinstance(kev, (set, frozenset)):
        kev = None
    notes = [error] if error else []
    if kev is None:
        notes.append("CISA KEV unavailable; exploitation status unknown.")
    for item in candidates:
        key = str(item.get("id", "")).upper()
        item.update(epss.get(key, {}))
        item["kev_status"] = "unknown" if kev is None else "listed" if key in kev else "not-listed" if key in ids else "not-applicable"
        epss_score = _safe_numeric_score(item, "epss", 1)
        cvss_score = _safe_numeric_score(item, "cvss_score", 10)
        item["priority_label"] = (
            "known-exploited" if item["kev_status"] == "listed"
            else "high-epss" if epss_score >= 0.5
            else "high-cvss" if cvss_score >= 9
            else "review"
        )
    candidates.sort(
        key=lambda x: (
            x["kev_status"] == "listed",
            _safe_numeric_score(x, "epss", 1),
            _safe_numeric_score(x, "cvss_score", 10),
        ), reverse=True,
    )
    return candidates, notes
