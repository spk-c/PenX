"""Shodan enrichment for authorized passive IP research.

InternetDB is a third-party *historical index*, not a live scan. Its CVE
matches include unverified associations and never confirm exploitability.
Only public IPv4 addresses are sent to Shodan in this integration.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
from typing import Callable
from urllib.parse import quote

import requests

INTERNETDB_BASE = "https://internetdb.shodan.io/"
SHODAN_HOST_BASE = "https://api.shodan.io/shodan/host/"
SHODAN_INFO_URL = "https://api.shodan.io/api-info"
CVE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.I)


def _text_list(value: object, limit: int, width: int = 200) -> list[str]:
    if not isinstance(value, list):
        return []
    result = []
    for entry in value[:limit * 2]:
        if not isinstance(entry, str):
            continue
        cleaned = entry.strip()[:width]
        if cleaned and cleaned not in result:
            result.append(cleaned)
        if len(result) == limit:
            break
    return result


def _ports(value: object) -> list[int]:
    if not isinstance(value, list):
        return []
    return sorted({v for v in value[:500] if type(v) is int and 1 <= v <= 65535})[:100]


def _global_ipv4(value: str) -> str | None:
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    return str(ip) if ip.version == 4 and ip.is_global else None


def resolve_public_ipv4(host: str, limit: int = 3, *, dns_resolve=None) -> tuple[list[str], str]:
    """Use a DNS resolver only; never open a connection to the assessed host.

    The caller already validated the host via tools._host().
    """
    limit = max(1, min(int(limit), 5))
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        if ip.version == 6:
            return [], "IPv6 is not supported by the InternetDB lookup; skipped."
        if not ip.is_global:
            return [], "Non-public IP: Shodan lookup skipped."
        return [str(ip)], ""
    try:
        import dns.resolver
        resolver = dns.resolver.resolve if dns_resolve is None else dns_resolve
        answer = resolver(host, "A", lifetime=6)
    except Exception as exc:
        return [], f"DNS A lookup unavailable ({type(exc).__name__})."
    ips = []
    for item in answer:
        resolved = _global_ipv4(str(item))
        if resolved and resolved not in ips:
            ips.append(resolved)
        if len(ips) >= limit:
            break
    if not ips:
        return [], "No public IPv4 A records returned; Shodan lookup skipped."
    return ips, f"Using up to {limit} public DNS A records; shared/CDN IPs may serve other domains."


def normalize_internetdb(data: object, expected_ip: str) -> dict:
    if not isinstance(data, dict):
        raise ValueError("Unexpected InternetDB response.")
    if data.get("ip") != expected_ip:
        raise ValueError("InternetDB returned a different IP.")
    return {
        "ip": expected_ip,
        "ports": _ports(data.get("ports")),
        "cpes": _text_list(data.get("cpes"), 40, 300),
        "hostnames": _text_list(data.get("hostnames"), 30, 253),
        "tags": _text_list(data.get("tags"), 30, 80),
        "vulns": [v for v in _text_list(data.get("vulns"), 100, 24) if CVE.fullmatch(v)],
        "source": "Shodan InternetDB",
        "verification": "unverified external index candidate; not a confirmed vulnerability",
    }


def normalize_premium_host(data: object, expected_ip: str) -> dict:
    if not isinstance(data, dict) or data.get("ip_str") != expected_ip:
        raise ValueError("Unexpected Shodan Host API response.")
    services = []
    for row in data.get("data", [])[:30] if isinstance(data.get("data"), list) else []:
        if not isinstance(row, dict):
            continue
        port = row.get("port")
        if type(port) is not int or port < 1 or port > 65535:
            continue
        services.append({
            "port": port,
            "transport": str(row.get("transport") or "")[:12],
            "product": str(row.get("product") or "")[:100],
            "version": str(row.get("version") or "")[:100],
            "last_seen": str(row.get("timestamp") or "")[:40],
        })
    return {
        "ip": expected_ip,
        "ports": _ports(data.get("ports")),
        "org": str(data.get("org") or "")[:160],
        "asn": str(data.get("asn") or "")[:45],
        "services": services,
        "source": "Shodan Host API",
        "verification": "external historical observation; not a live target measurement",
    }


def format_api_error(exc: Exception, source: str) -> str:
    """Don't leak request URLs or API keys from exception messages."""
    status = getattr(getattr(exc, "response", None), "status_code", None)
    if status == 404:
        return f"[{source}] No indexed data for this IP (404)."
    if status in (401, 403):
        return f"[{source}] API key invalid or subscription access denied ({status})."
    if status == 402:
        return f"[{source}] API plan or credits do not allow this lookup (402)."
    if status == 429:
        return f"[{source}] Rate limited (429); no automatic retry."
    if status is not None:
        return f"[{source}] API unavailable (HTTP {status})."
    if isinstance(exc, requests.Timeout):
        return f"[{source}] Request timed out."
    if isinstance(exc, requests.RequestException):
        return f"[{source}] Network/API connection failed."
    return f"[{source}] Invalid or oversized provider response ({type(exc).__name__})."


def enrich_target(
    host: str, query_json: Callable, *,
    include_paid: bool = True, max_ips: int = 3,
    api_key: str | None = None, free_enabled: bool = True,
    resolve_ips=None,
) -> list[str]:
    """Return bounded text records for passive_recon; no direct target scans.

    Query function performs requests only to hardcoded Shodan HTTPS endpoints.
    The premium key is never included in the returned text or logs.
    """
    key = (api_key if api_key is not None else os.getenv("PENX_SHODAN_API_KEY", "")).strip()
    if not free_enabled and not (include_paid and key):
        return ["[SHODAN LOOKUP] Disabled by PENX_SHODAN_INTERNETDB=off."]
    resolver = resolve_public_ipv4 if resolve_ips is None else resolve_ips
    supplied_ips, note = resolver(host, max_ips)
    # A substituted DNS resolver is still untrusted input. Do not query a
    # third-party service for private, reserved or malformed addresses.
    ips = []
    for value in supplied_ips:
        ip = _global_ipv4(value) if isinstance(value, str) else None
        if ip and ip not in ips:
            ips.append(ip)
        if len(ips) >= max(1, min(int(max_ips), 5)):
            break
    messages = [f"[SHODAN LOOKUP] {note}"] if note else []
    if not ips:
        return messages or ["[SHODAN LOOKUP] No public IPv4 addresses; skipped."]
    paid_blocked = False
    if include_paid and key:
        try:
            info = query_json(SHODAN_INFO_URL, params={"key": key}, allow_redirects=False)
            if not isinstance(info, dict):
                raise ValueError("Invalid API account response.")
            summary = {
                "plan": str(info.get("plan") or "unknown")[:60],
                "query_credits": info.get("query_credits") if type(info.get("query_credits")) is int else None,
                "unlocked": bool(info.get("unlocked", False)),
            }
            messages.append("[SHODAN ACCOUNT STATUS]\n" +
                            json.dumps(summary, ensure_ascii=False))
        except (requests.RequestException, ValueError, TypeError) as exc:
            messages.append(format_api_error(exc, "SHODAN ACCOUNT STATUS"))
            if getattr(getattr(exc, "response", None), "status_code", None) in (
                401, 402, 403, 429
            ):
                paid_blocked = True
    for ip in ips:
        if free_enabled:
            try:
                data = query_json(INTERNETDB_BASE + quote(ip, safe=""), allow_redirects=False)
                record = normalize_internetdb(data, ip)
                messages.append("[SHODAN INTERNETDB RECORD]\n" +
                                json.dumps(record, ensure_ascii=False, sort_keys=True))
            except (requests.RequestException, ValueError, TypeError) as exc:
                messages.append(format_api_error(exc, f"SHODAN INTERNETDB {ip}"))
        if not (include_paid and key) or paid_blocked:
            continue
        try:
            data = query_json(SHODAN_HOST_BASE + quote(ip, safe=""), params={"key": key},
                              allow_redirects=False)
            record = normalize_premium_host(data, ip)
            messages.append("[SHODAN HOST API RECORD]\n" +
                            json.dumps(record, ensure_ascii=False, sort_keys=True))
        except (requests.RequestException, ValueError, TypeError) as exc:
            messages.append(format_api_error(exc, f"SHODAN HOST API {ip}"))
            if getattr(getattr(exc, "response", None), "status_code", None) in (
                401, 402, 403, 429
            ):
                paid_blocked = True
    messages.append(
        "[SHODAN EVIDENCE LIMITATION] InternetDB is a periodically refreshed external "
        "IP index. Its CVE list may contain unverified version-based associations. "
        "Observed ports may belong to another tenant of a shared hosting/CDN IP. "
        "Do not mark issues confirmed, exploitable, fixed, or live based on this data."
    )
    return messages
