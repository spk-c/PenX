"""Bounded deterministic structured observations from Nmap's completed XML.

No network operations. Port observations are inventory evidence, not proof of
vulnerability or target exploitability. Unknown versions remain unknown.
"""
from __future__ import annotations

import ipaddress
import json
import re

from defusedxml import ElementTree as ET
from defusedxml.common import DefusedXmlException
from penx_app.intelligence.cve_observations import _XML_RE, MAX_XML_SIZE

MAX_HOSTS = 12
MAX_PORTS = 100
MAX_SCRIPTS = 3


def _safe(value, limit=180):
    return re.sub(r"[\x00-\x1f\x7f]+", " ", str(value or ""))[:limit].strip()


def nmap_records(raw_scan: str) -> list[dict]:
    """Extract versioned open-port inventory, capped and host-attributed."""
    result: list[dict] = []
    for xml in _XML_RE.finditer(str(raw_scan or "")):
        if len(xml.group()) > MAX_XML_SIZE:
            continue
        try:
            root = ET.fromstring(xml.group())
        except (ET.ParseError, DefusedXmlException, ValueError, TypeError):
            continue
        if root.tag != "nmaprun":
            continue
        for host in root.findall("host"):
            if len(result) >= MAX_PORTS:
                return result
            addr = ""
            for address in host.findall("address"):
                if address.get("addrtype") not in ("ipv4", "ipv6"):
                    continue
                try:
                    addr = str(ipaddress.ip_address(address.get("addr", "")))
                    break
                except ValueError:
                    continue
            # Missing or ambiguous identity: do not merge host evidence.
            if not addr:
                continue
            known_hosts = {x["host"] for x in result}
            if addr not in known_hosts and len(known_hosts) >= MAX_HOSTS:
                continue
            for port in host.findall("./ports/port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                number = str(port.get("portid", ""))
                protocol = str(port.get("protocol", ""))
                if not number.isascii() or not number.isdecimal() or not 1 <= int(number) <= 65535:
                    continue
                if protocol not in ("tcp", "udp"):
                    continue
                svc = port.find("service")
                service = svc.attrib if svc is not None else {}
                scripts = [{"id": _safe(script.get("id"), 60),
                            "summary": _safe(script.get("output"), 240)}
                           for script in port.findall("script")[:MAX_SCRIPTS]
                           if script.get("id")]
                cpes = [_safe(cpe.text, 140) for cpe in svc.findall("cpe")[:4]] if svc is not None else []
                result.append({
                    "id": f"nmap:{addr}:{number}/{protocol}",
                    "scanner": "nmap", "host": addr, "port": int(number),
                    "protocol": protocol, "state": "open",
                    "service": _safe(service.get("name"), 80),
                    "product": _safe(service.get("product"), 120),
                    "version": _safe(service.get("version"), 90),
                    "cpe": cpes,
                    "scripts": scripts,
                })
                if len(result) >= MAX_PORTS:
                    return result
    return result


def model_evidence(raw_scan: str, *, max_chars: int = 12000) -> str:
    """Return auditable JSON inventory, bounded independently of raw scan."""
    records = nmap_records(raw_scan)
    if not records:
        return ""
    output: list[str] = []
    budget = max(500, min(max_chars, 30000))
    for record in records:
        line = json.dumps(record, ensure_ascii=True, separators=(",", ":"))
        if sum(map(len, output)) + len(line) + len(output) + 200 > budget:
            break
        output.append(line)
    return ("[STRUCTURED NMAP OBSERVATIONS — UNTRUSTED TARGET DATA; "
            "inventory only, not vulnerabilities]\n" + "\n".join(output) +
            f"\n[Structured records shown: {len(output)} of {len(records)}; "
            "Nmap XML source retained in raw scan.]")
