"""Source-only reconnaissance: never connect to the assessed host.

Passive here means queries to third-party registries, resolvers and indexes.
Those providers receive the lookup term. No HTTP requests to the target.
"""
from __future__ import annotations

import ipaddress
import json
import os
from urllib.parse import quote

import requests

from penx_app.scanners.scanner_targets import normalize_host as _host
from penx_app.intelligence.shodan_enrichment import enrich_target


_MAX_BYTES = 200_000
_TIMEOUT = (5, 12)


def _query_json(url: str, *, params: dict | None = None, auth=None,
                allow_redirects: bool = False, control=None) -> object:
    timeout = _TIMEOUT if control is None else (min(1, control()), min(1, control()))
    response = requests.get(url, params=params, auth=auth, timeout=timeout,
                            headers={"User-Agent": "PenX/2.0 passive-recon",
                                     "Accept": "application/json"},
                            allow_redirects=allow_redirects, stream=True)
    try:
        response.raise_for_status()
        # Bound third-party data so large registries cannot exhaust memory.
        pieces, total = [], 0
        for chunk in response.iter_content(chunk_size=8192):
            if control is not None:
                control()
            total += len(chunk)
            if total > _MAX_BYTES:
                raise ValueError("Source response exceeded 200 KB.")
            pieces.append(chunk)
        if control is not None:
            control()
        return json.loads(b"".join(pieces).decode("utf-8"))
    finally:
        response.close()


def _compact(value: object, limit: int = 6000) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)[:limit]


def _dns_lookup(name: str) -> str:
    try:
        import dns.resolver
    except ImportError:
        return "dnspython unavailable."
    lines = []
    for rrtype in ("A", "AAAA", "MX", "NS", "TXT"):
        try:
            records = dns.resolver.resolve(name, rrtype, lifetime=5)
            values = [str(x)[:350] for x in list(records)[:15]]
            lines.append(f"{rrtype}: " + "; ".join(values))
        except Exception as exc:
            # DNS unavailable does not imply that no records exist.
            lines.append(f"{rrtype}: unavailable ({type(exc).__name__})")
    return "\n".join(lines)


def passive_recon(target: str, *, include_paid: bool = True) -> str:
    """Fetch external metadata only. Caller must not enable active LLM tools."""
    host = _host(target)
    if "/" in host:
        raise ValueError("Passive reconnaissance requires one host, not a CIDR.")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    results = [
        f"[PASSIVE-ONLY RECON: {host}]",
        "Only external data sources queried. No direct TCP/HTTP connection "
        "to the assessed host. Third-party services receive the lookup value."
    ]
    if ip is None:
        from penx_app.scanners.tools import run_whois
        results.append("[WHOIS REGISTRY]\n" + run_whois(host))
        results.append("[DNS VIA RESOLVER]\n" + _dns_lookup(host))
        try:
            ct = _query_json("https://crt.sh/", params={"q": f"%.{host}",
                                                        "output": "json"})
            # Limit certificates to a concise, inspectable sample.
            names = []
            for cert in ct if isinstance(ct, list) else []:
                if not isinstance(cert, dict):
                    continue
                for name in str(cert.get("name_value", "")).splitlines():
                    if name not in names:
                        names.append(name)
                    if len(names) >= 30:
                        break
                if len(names) >= 30:
                    break
            results.append("[CERTIFICATE TRANSPARENCY]\n" +
                           (_compact(names) if names else "No entries returned."))
        except (requests.RequestException, ValueError, KeyError) as exc:
            results.append("[CERTIFICATE TRANSPARENCY] Unavailable: " + type(exc).__name__)
    try:
        kind = "ip" if ip is not None else "domain"
        rdap = _query_json(f"https://rdap.org/{kind}/{quote(host, safe='')}")
        if isinstance(rdap, dict):
            reduced = {k: rdap.get(k) for k in
                       ("name", "handle", "status", "events", "nameservers",
                        "startAddress", "endAddress") if k in rdap}
            results.append("[RDAP]\n" + _compact(reduced))
        else:
            results.append("[RDAP] No structured response.")
    except (requests.RequestException, ValueError, KeyError) as exc:
        results.append("[RDAP] Unavailable: " + type(exc).__name__)

    # Free InternetDB is always queried for public IPv4, even without a key.
    # Each external record is labeled so it cannot be mistaken for a live scan.
    max_ips_setting = os.getenv("PENX_SHODAN_MAX_IPS", "3")
    try:
        max_ips = max(1, min(int(max_ips_setting), 5))
    except ValueError:
        max_ips = 3
    internetdb_enabled = os.getenv("PENX_SHODAN_INTERNETDB", "on").lower() not in (
        "off", "false", "no", "0"
    )
    results.extend(enrich_target(host, _query_json, include_paid=include_paid,
                                 max_ips=max_ips, free_enabled=internetdb_enabled))

    # Preserve the independent optional Censys index lookup for public IPs.
    if include_paid and ip is not None and ip.is_global:
        censys_id = os.getenv("PENX_CENSYS_API_ID", "").strip()
        censys_secret = os.getenv("PENX_CENSYS_API_SECRET", "").strip()
        if censys_id and censys_secret:
            try:
                result = _query_json("https://search.censys.io/api/v2/hosts/" +
                                     quote(host, safe=""), auth=(censys_id, censys_secret))
                if isinstance(result, dict):
                    payload = result.get("result")
                    services = payload.get("services") if isinstance(payload, dict) else None
                    if not isinstance(services, list):
                        # A malformed provider reply is unavailable, not an
                        # authoritative empty service inventory.
                        raise ValueError("Invalid Censys service records")
                    results.append("[CENSYS HISTORICAL INDEX]\n" + _compact([
                        {"port": x.get("port"), "service_name": x.get("service_name"),
                         "transport_protocol": x.get("transport_protocol")}
                        for x in services[:30] if isinstance(x, dict)
                    ]))
            except (requests.RequestException, ValueError, KeyError) as exc:
                results.append("[CENSYS] Unavailable: " + type(exc).__name__)
    return "\n\n".join(results)
