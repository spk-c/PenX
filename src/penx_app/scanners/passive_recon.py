"""Source-only reconnaissance: never connect to the assessed host.

Passive here means queries to third-party registries, resolvers and indexes.
Those providers receive the lookup term. No HTTP requests to the target.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
from itertools import islice
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
    from penx_app.scanners.tools import _bounded_dns_values, _dns_loss_notes
    lines = []
    for rrtype in ("A", "AAAA", "MX", "NS", "TXT"):
        try:
            records = dns.resolver.resolve(name, rrtype, lifetime=5)
            values, omitted, truncated = _bounded_dns_values(records, 15)
            detail = f"{rrtype}: " + "; ".join(values)
            notes = _dns_loss_notes(rrtype, omitted, truncated)
            if notes:
                detail += "\n(!) " + "; ".join(notes)
            lines.append(detail)
        except Exception as exc:
            # DNS unavailable does not imply that no records exist.
            lines.append(f"{rrtype}: unavailable ({type(exc).__name__})")
    return "\n".join(lines)


# --- PX-303: read-only DNS/email-domain posture (no mail, no selector guessing) ---

_STATE_MISSING = "missing"
_STATE_UNKNOWN = "unknown"
_POSTURE_MAX_SELECTORS = 8
_STATE_CONFIGURED = "configured-but-unverified"
_STATE_MISCONFIGURED = "observed-misconfiguration"
_POSTURE_VALUE_LIMIT = 350
_POSTURE_MAX_RECORDS = 5


def _record_text(rdata) -> str:
    """Render an rdata value. TXT uses the logical text (strings concatenated
    without a separator); all other types use the standard text form."""
    strings = getattr(rdata, "strings", None)
    if isinstance(strings, (tuple, list)) and strings:
        return b"".join(strings).decode("ascii", "replace")
    return rdata.to_text()


def _bound_posture_values(texts, max_records: int = _POSTURE_MAX_RECORDS,
                          max_chars: int = _POSTURE_VALUE_LIMIT):
    """Render record texts under an explicit count and size budget.

    Returns (values, omitted, truncated).
    """
    values: list[str] = []
    omitted, truncated = 0, 0
    for text in texts:
        if len(values) >= max_records:
            omitted += 1
            continue
        if len(text) > max_chars:
            text = text[:max_chars]
            truncated += 1
        values.append(text)
    return values, omitted, truncated


def _posture_loss_notes(label: str, omitted: int, truncated: int) -> list:
    parts = []
    if omitted:
        parts.append(f"{omitted} more {label} record(s) omitted for display")
    if truncated:
        parts.append(f"{truncated} {label} value(s) truncated to {_POSTURE_VALUE_LIMIT} chars")
    return parts


def _posture_record(state, *, evidence, count, values, reason=""):
    return {"state": state, "evidence": evidence, "count": count,
            "values": values, "reason": reason}


def _posture_resolve(resolver, host: str, rrtype: str):
    """Return (texts, error_name). error_name is None on success."""
    try:
        answer = resolver(host, rrtype, lifetime=5)
    except Exception as exc:
        return [], type(exc).__name__
    return [_record_text(r) for r in answer], None


def _resolver_failure(error_name: str):
    missing = error_name in ("NXDOMAIN", "NoAnswer")
    return _posture_record(
        _STATE_MISSING if missing else _STATE_UNKNOWN,
        evidence=False, count=0, values=[],
        reason="no record" if missing else f"resolver error ({error_name})",
    )


def _extract_dmarc_policy(text: str):
    """Parse semicolon-delimited tags; reject duplicate or malformed tags."""
    tags = {}
    for part in text.split(";"):
        part = part.strip()
        if not part:
            continue
        key, sep, value = part.partition("=")
        key, value = key.strip().lower(), value.strip().lower()
        if not sep or not key or not value or key in tags:
            return None
        tags[key] = value
    if next(iter(tags), None) != "v" or tags.get("v") != "dmarc1":
        return None
    policy = tags.get("p")
    return policy if policy in ("none", "quarantine", "reject") else None


def _posture_mx(resolver, host: str, diagnostics: list):
    texts, err = _posture_resolve(resolver, host, "MX")
    if err is not None:
        return _resolver_failure(err)
    values, omitted, truncated = _bound_posture_values(texts)
    if notes := _posture_loss_notes("MX", omitted, truncated):
        diagnostics.extend(notes)
    if not texts:
        return _posture_record(_STATE_MISSING, evidence=False, count=0, values=[],
                               reason="no record")
    return _posture_record(_STATE_CONFIGURED, evidence=True, count=len(texts),
                           values=values)


def _posture_spf(resolver, host: str, diagnostics: list):
    texts, err = _posture_resolve(resolver, host, "TXT")
    if err is not None:
        return _resolver_failure(err)
    spf = [t for t in texts if re.match(r"^v=spf1(?:\s|$)", t, re.I)]
    if not spf:
        return _posture_record(_STATE_MISSING, evidence=False, count=0, values=[],
                               reason="no SPF record")
    values, omitted, truncated = _bound_posture_values(spf)
    if notes := _posture_loss_notes("SPF", omitted, truncated):
        diagnostics.extend(notes)
    if len(spf) != 1:
        return _posture_record(_STATE_MISCONFIGURED, evidence=True, count=len(spf),
                               values=values, reason="multiple SPF records")
    terms = spf[0].lower().split()[1:]
    catch_all = next((term for term in terms
                      if term in ("all", "+all", "-all", "~all", "?all")), None)
    if catch_all in ("all", "+all", "?all"):
        return _posture_record(_STATE_MISCONFIGURED, evidence=True, count=1,
                               values=values, reason="permissive SPF catch-all")
    if catch_all == "~all":
        return _posture_record(_STATE_CONFIGURED, evidence=True, count=1,
                               values=values, reason="softfail policy (~all)")
    if catch_all == "-all" or any(term.startswith("redirect=") and
                                  term != "redirect=" for term in terms):
        return _posture_record(_STATE_CONFIGURED, evidence=True, count=1,
                               values=values)
    return _posture_record(_STATE_MISCONFIGURED, evidence=True, count=1,
                           values=values, reason="no default-refuse mechanism")


def _posture_dmarc(resolver, host: str, diagnostics: list):
    texts, err = _posture_resolve(resolver, "_dmarc." + host, "TXT")
    if err is not None:
        return _resolver_failure(err)
    dmarc = [t for t in texts if re.match(r"^v\s*=\s*dmarc1(?:\s|;|$)", t, re.I)]
    if not dmarc:
        return _posture_record(_STATE_MISSING, evidence=False, count=0, values=[],
                               reason="no DMARC record")
    values, omitted, truncated = _bound_posture_values(dmarc)
    if notes := _posture_loss_notes("DMARC", omitted, truncated):
        diagnostics.extend(notes)
    policy = _extract_dmarc_policy(dmarc[0])
    if len(dmarc) != 1 or policy is None:
        return _posture_record(_STATE_MISCONFIGURED, evidence=True, count=len(dmarc),
                               values=values, reason="invalid or multiple DMARC policies")
    if policy == "none":
        return _posture_record(_STATE_MISCONFIGURED, evidence=True, count=len(dmarc),
                               values=values, reason="no policy enforcement (p=none)")
    return _posture_record(_STATE_CONFIGURED, evidence=True, count=len(dmarc),
                           values=values)


def _posture_mta_sts(resolver, host: str, diagnostics: list):
    texts, err = _posture_resolve(resolver, "_mta-sts." + host, "TXT")
    if err is not None:
        return _resolver_failure(err)
    mta = [t for t in texts if t.lower().startswith("v=mta-sts")]
    if not mta:
        return _posture_record(_STATE_MISSING, evidence=False, count=0, values=[],
                               reason="no MTA-STS record")
    values, omitted, truncated = _bound_posture_values(mta)
    if notes := _posture_loss_notes("MTA-STS", omitted, truncated):
        diagnostics.extend(notes)
    return _posture_record(_STATE_CONFIGURED, evidence=True, count=len(mta),
                           values=values)


def _posture_caa(resolver, host: str, diagnostics: list):
    texts, err = _posture_resolve(resolver, host, "CAA")
    if err is not None:
        return _resolver_failure(err)
    values, omitted, truncated = _bound_posture_values(texts)
    if notes := _posture_loss_notes("CAA", omitted, truncated):
        diagnostics.extend(notes)
    if not texts:
        return _posture_record(_STATE_MISSING, evidence=False, count=0, values=[],
                               reason="no record")
    return _posture_record(_STATE_CONFIGURED, evidence=True, count=len(texts),
                           values=values)


def _posture_dkim(resolver, host: str, selectors, diagnostics: list):
    selectors = list(selectors)
    if not selectors:
        return _posture_record(_STATE_UNKNOWN, evidence=False, count=0, values=[],
                               reason="no DKIM selectors provided")
    texts, error_names = [], []
    for selector in selectors:
        # Only explicitly provided selectors are queried; nothing is guessed.
        record, err = _posture_resolve(resolver, f"{selector}._domainkey.{host}", "TXT")
        if err is not None:
            error_names.append(err)
        else:
            texts.extend(record)
    if texts:
        values, omitted, truncated = _bound_posture_values(texts)
        if notes := _posture_loss_notes("DKIM", omitted, truncated):
            diagnostics.extend(notes)
        return _posture_record(_STATE_CONFIGURED, evidence=True, count=len(texts),
                               values=values)
    reason = ("resolver error"
              if any(e not in ("NXDOMAIN", "NoAnswer") for e in error_names)
              else "no DKIM record")
    return _posture_record(_STATE_UNKNOWN if reason == "resolver error" else _STATE_MISSING,
                           evidence=False, count=0, values=[], reason=reason)


def _posture_dnssec(resolver, host: str, diagnostics: list):
    texts, err = _posture_resolve(resolver, host, "DNSKEY")
    if err is not None:
        return _resolver_failure(err)
    values, omitted, truncated = _bound_posture_values(texts)
    if notes := _posture_loss_notes("DNSKEY", omitted, truncated):
        diagnostics.extend(notes)
    if not texts:
        return _posture_record(_STATE_MISSING, evidence=False, count=0, values=[],
                               reason="no DNSKEY record")
    return _posture_record(_STATE_CONFIGURED, evidence=True, count=len(texts),
                           values=values)


def dns_email_posture(host: str, *, resolver=None, dkim_selectors=()) -> dict:
    """Read-only DNS/email-domain posture report for an authorized domain.

    Parses MX, SPF, DMARC, CAA, DKIM (explicit selectors only), MTA-STS and the
    DNSSEC signal. Each record type is classified as missing (no data),
    unknown (not assessed or resolver failure),
    configured-but-unverified (record present, not verified) or
    observed-misconfiguration (a clear posture gap is visible). Never sends mail,
    never guesses DKIM selectors and never connects to the assessed host.
    The caller must enforce domain authorization before invoking this helper.
    At most eight explicit selectors and six fixed lookups are allowed; each
    resolver call has a five-second lifetime. DNSKEY presence is not proof
    of a validated DNSSEC chain. SPF and DMARC are local policy hints, not
    end-to-end mail authentication validation.
    """
    host = _host(host)
    if isinstance(dkim_selectors, (str, bytes)):
        raise ValueError("DKIM selectors must be an iterable of explicit names")
    dkim_selectors = tuple(islice(dkim_selectors, _POSTURE_MAX_SELECTORS + 1))
    if len(dkim_selectors) > _POSTURE_MAX_SELECTORS:
        raise ValueError("Too many DKIM selectors")
    for selector in dkim_selectors:
        if not isinstance(selector, str) or not re.fullmatch(
                r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", selector):
            raise ValueError("Invalid DKIM selector")
        if len(selector) + len("._domainkey.") + len(host) > 253:
            raise ValueError("DKIM name exceeds DNS name limit")
    dkim_selectors = tuple(dict.fromkeys(x.lower() for x in dkim_selectors))
    if resolver is None:
        try:
            import dns.resolver
        except ImportError:
            raise ValueError("dnspython is required for DNS posture analysis.") from None
        resolver = dns.resolver.resolve
    diagnostics: list = []
    records = {
        "mx": _posture_mx(resolver, host, diagnostics),
        "spf": _posture_spf(resolver, host, diagnostics),
        "dmarc": _posture_dmarc(resolver, host, diagnostics),
        "mta_sts": _posture_mta_sts(resolver, host, diagnostics),
        "caa": _posture_caa(resolver, host, diagnostics),
        "dkim": _posture_dkim(resolver, host, dkim_selectors, diagnostics),
        "dnssec": _posture_dnssec(resolver, host, diagnostics),
    }
    summary = {
        "missing": sum(1 for r in records.values() if r["state"] == _STATE_MISSING),
        "unknown": sum(1 for r in records.values() if r["state"] == _STATE_UNKNOWN),
        "configured-but-unverified": sum(1 for r in records.values()
                                         if r["state"] == _STATE_CONFIGURED),
        "observed-misconfiguration": sum(1 for r in records.values()
                                         if r["state"] == _STATE_MISCONFIGURED),
        "evidence": any(r["evidence"] for r in records.values()),
    }
    return {
        "schema": "penx-dns-email-posture-v1",
        "host": host,
        "records": records,
        "summary": summary,
        "diagnostics": "; ".join(diagnostics),
    }


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
