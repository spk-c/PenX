"""Vendor-maintained advisory context; no automatic assertion of package patch state."""
from functools import lru_cache
import re
import requests
from penx_app.intelligence.package_inventory import package_status
from pathlib import Path
import json

CVE = re.compile(r"^CVE-\d{4}-\d{4,8}$", re.I)
REDHAT = "https://access.redhat.com/hydra/rest/securitydata/cve/"
UBUNTU = "https://ubuntu.com/security/cves/"
DEBIAN = "https://security-tracker.debian.org/tracker/"

def _advisory_json(url: str, *, http_get=None):
    """Bounded, redirect-free vendor request; never expose a provider error."""
    client = requests.get if http_get is None else http_get
    try:
        res = client(url, timeout=(3, 8), allow_redirects=False)
        res.raise_for_status()
        return res.json()
    except (requests.RequestException, ValueError, TypeError):
        return None


@lru_cache(maxsize=50)
def redhat_data(cve):
    return _advisory_json(REDHAT + cve + ".json")


@lru_cache(maxsize=50)
def ubuntu_data(cve):
    return _advisory_json(UBUNTU + cve + ".json")


def fetch_redhat_data(cve: str, *, http_get=None):
    """An injected provider never reads or populates the production cache."""
    if http_get is None:
        return redhat_data(cve)
    return _advisory_json(REDHAT + cve + ".json", http_get=http_get)


def fetch_ubuntu_data(cve: str, *, http_get=None):
    """An injected provider never reads or populates the production cache."""
    if http_get is None:
        return ubuntu_data(cve)
    return _advisory_json(UBUNTU + cve + ".json", http_get=http_get)


def _installed_for_row(row: dict, inventory: dict, *, fixed: str = "") -> dict:
    """Installed-source comparison only when vendor status supplies a real fix."""
    src = str(row.get("package", "")).lower()
    if not inventory or not src:
        return {}
    if fixed and not fixed.startswith(("n/a", "None")):
        return package_status(src, fixed, inventory)
    version = inventory.get("packages", {}).get(src)
    return ({"installed_version": version,
             "installed_status": "no-comparable-published-fix"}
            if version else {"installed_status": "no-exact-package-match"})

@lru_cache(maxsize=2)
def _read_debian_snapshot(path_string: str, modified: int):
    path = Path(path_string)
    if path.stat().st_size > 30_000_000:
        raise ValueError("Debian tracker snapshot exceeds 30 MB.")
    return json.loads(path.read_text(encoding="utf-8"))


def _debian_tracker_entry(cve: str, package: str, release: str,
                          filename: str) -> dict | None:
    """Resolve one source/release/CVE from explicit local Debian tracker JSON.

    The export is not a stable upstream API; unexpected shapes fail closed.
    """
    if not filename:
        return None
    path = Path(filename).expanduser()
    try:
        db = _read_debian_snapshot(str(path.resolve()), path.stat().st_mtime_ns)
        record = ((db.get(package) or {}).get(cve) or {}).get("releases", {}).get(release)
        return record if isinstance(record, dict) else None
    except (OSError, ValueError, TypeError, AttributeError):
        return None


def _safe_lookup(lookup, cve: str):
    """Injected provider failures are unavailable, never negative patch evidence."""
    try:
        return lookup(cve)
    except (requests.RequestException, ValueError, TypeError):
        return None


def vendor_guidance(candidate, *, distro_hint="", inventory=None,
                    debian_tracker_file="", ubuntu_lookup=None, redhat_lookup=None):
    """Vendor/source-package status, never an assertion of remotely confirmed impact.

    Inventory is user-provided and names SOURCE packages, not HTTP/SSH banners.
    """
    cve = str(candidate.get("id", "")).upper()
    if not CVE.fullmatch(cve):
        return []
    inv = inventory or {}
    kind, _, codename = distro_hint.lower().partition(":")
    if inv:
        if kind and (kind != inv["distro"] or codename != inv["release"]):
            return [{"source":"Inventory", "status":"inventory-release-conflict",
                     "url":""}]
        kind, codename = inv["distro"], inv["release"]

    if kind == "debian":
        link = DEBIAN + cve
        if not inv:
            return [{"source":"Debian Security Tracker", "status":"provide-source-package-inventory",
                     "url":link}]
        if not debian_tracker_file:
            return [{"source":"Debian Security Tracker", "status":"tracker-snapshot-not-configured",
                     "url":link}]
        results = []
        for pkg in list(inv["packages"])[:30]:
            record = _debian_tracker_entry(cve,pkg,codename,debian_tracker_file)
            if not record:
                continue
            fixed = str(record.get("fixed_version") or "")
            status = str(record.get("status") or "unknown")
            row = {"source":"Debian Security Tracker","package":pkg,"release":codename,
                   "status":status,"fixed_version":fixed,"url":link}
            if fixed == "0":
                row["installed_status"] = "vendor-says-not-affected"
                row["installed_version"] = inv["packages"][pkg]
            elif fixed:
                row.update(_installed_for_row(row, inv, fixed=fixed))
            else:
                row.update(_installed_for_row(row, inv))
            results.append(row)
            if len(results) >= 10:
                break
        return results or [{"source":"Debian Security Tracker",
                            "status":"no-package-cve-record-found","url":link}]

    if kind == "ubuntu":
        obj = _safe_lookup(ubuntu_data if ubuntu_lookup is None else ubuntu_lookup, cve)
        if not isinstance(obj, dict):
            return [{"source":"Ubuntu Security","status":"unavailable","url":UBUNTU+cve}]
        results = []
        packages = obj.get("packages", [])
        for pkg in packages if isinstance(packages, list) else []:
            if not isinstance(pkg, dict):
                continue
            source = str(pkg.get("name","")).lower()
            if inv and source not in inv["packages"]:
                continue
            statuses = pkg.get("statuses", [])
            for state in statuses if isinstance(statuses,list) else []:
                if not isinstance(state,dict) or str(state.get("release_codename","")) != codename:
                    continue
                status = str(state.get("status") or "untriaged").lower()
                detail = str(state.get("description") or "").strip()
                # Only use an exact version token. Freeform advisory text is NOT a version.
                from penx_app.intelligence.package_inventory import _VERSION
                fixed = detail if _VERSION.fullmatch(detail) else ""
                row = {"source":"Ubuntu Security","package":source,"release":codename,
                       "status":status,"fixed_version":fixed,
                       "description":detail[:180],"url":UBUNTU+cve}
                if inv:
                    if status in ("not affected","not-affected"):
                        row["installed_version"] = inv["packages"][source]
                        row["installed_status"] = "vendor-says-not-affected"
                    elif status in ("released","fixed") and fixed:
                        row.update(_installed_for_row(row, inv, fixed=fixed))
                    else:
                        row.update(_installed_for_row(row, inv))
                results.append(row)
                if len(results) >= 10:
                    return results
        return results or [{"source":"Ubuntu Security",
                            "status":"no-matching-release-package-status",
                            "release":codename,"url":UBUNTU+cve}]

    if kind in ("redhat","rhel"):
        obj = _safe_lookup(redhat_data if redhat_lookup is None else redhat_lookup, cve)
        if not isinstance(obj,dict):
            return [{"source":"Red Hat Security","status":"unavailable","url":REDHAT+cve}]
        results = []
        release = codename
        for entry in obj.get("package_state", []) if isinstance(obj.get("package_state"),list) else []:
            if not isinstance(entry,dict):
                continue
            product = str(entry.get("product_name",""))
            if release and release not in product.lower():
                continue
            source = str(entry.get("package_name","")).lower()
            if inv and source not in inv["packages"]:
                continue
            row = {"source":"Red Hat Security","package":source,"release":product,
                   "status":str(entry.get("fix_state","unknown")),"url":REDHAT+cve}
            if inv and source in inv["packages"]:
                row["installed_version"] = inv["packages"][source]
                row["installed_status"] = (
                    "vendor-says-not-affected"
                    if row["status"].lower() == "not affected"
                    else "no-comparable-published-fix")
            results.append(row)
        for entry in obj.get("affected_release",[]) if isinstance(obj.get("affected_release"),list) else []:
            if not isinstance(entry,dict):
                continue
            product = str(entry.get("product_name",""))
            if release and release not in product.lower():
                continue
            nvr = str(entry.get("package") or "")
            for source in (inv.get("packages") or {}) if inv else []:
                if not nvr.startswith(source + "-"):
                    continue
                suffix = nvr[len(source)+1:].replace(".src.rpm","")
                if "-" not in suffix:
                    continue
                version, revision = suffix.rsplit("-",1)
                fixed = version + "-" + revision
                row = {"source":"Red Hat Security","package":source,"release":product,
                       "status":"vendor-fix-published","fixed_version":fixed,
                       "url":str(entry.get("advisory") or REDHAT+cve)}
                row.update(_installed_for_row(row,inv,fixed=fixed))
                results.append(row)
                if len(results) >= 10:
                    return results
        return results[:10] or [{"source":"Red Hat Security",
                                "status":"no-matching-release-package-state","url":REDHAT+cve}]

    return [{"source":"Vendor references","status":"check-backports-and-version",
             "url":url} for url in candidate.get("vendor_advisories",[])[:2]]
