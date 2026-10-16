"""Extract trustworthy identifiers from authorized Nmap XML and explicit package URLs.

No hosts are contacted here. Nmap CPEs can be incorrect; they are only inputs to
catalogue searches, not evidence that software is vulnerable.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from urllib.parse import unquote

from defusedxml import ElementTree as ET
from defusedxml.common import DefusedXmlException

_XML_RE = re.compile(r"<nmaprun(?:\s[^>]*)?>.*?</nmaprun\s*>", re.S | re.I)
_PURL_RE = re.compile(r"\bpkg:(?:pypi|npm|maven|golang|cargo|gem|nuget|composer|deb|rpm)/[^\s<>'\"\[\]]{3,250}", re.I)
MAX_XML_SIZE = 2_000_000

@dataclass(frozen=True)
class Product:
    cpe: str
    label: str
    version: str
    port: str
    service: str
    evidence: str

@dataclass(frozen=True)
class Package:
    purl: str
    ecosystem: str
    name: str
    version: str

_PURL_TO_OSV = {
    "pypi": "PyPI", "npm": "npm", "maven": "Maven",
    "golang": "Go", "cargo": "crates.io", "gem": "RubyGems",
    "nuget": "NuGet", "composer": "Packagist",
    "deb": "Debian", "rpm": "Red Hat",
}
_PURL_TO_GH = {
    "pypi": "pip", "npm": "npm", "maven": "maven",
    "golang": "go", "cargo": "rust", "gem": "rubygems",
    "nuget": "nuget", "composer": "composer"
}

def normalize_cpe(cpe: str) -> str | None:
    """Support well-formed CPE 2.3 or the common Nmap cpe:/a:... format."""
    value = cpe.strip()
    if value.startswith("cpe:2.3:"):
        parts = value.split(":")
        if len(parts) != 13:
            return None
        if parts[2] not in ("a", "o", "h") or not parts[3] or not parts[4]:
            return None
        if any("/" in v or " " in v for v in parts):
            return None
        return value
    if value.startswith("cpe:/"):
        tail = value[len("cpe:/"):].split(":")
        if len(tail) < 4 or len(tail) > 7 or tail[0] not in ("a", "o", "h"):
            return None
        if any(not x or "/" in x or " " in x for x in tail[:4]):
            return None
        return "cpe:2.3:" + ":".join((tail + ["*"] * 11)[:11])
    return None

def cpe_components(cpe: str) -> tuple[str, str, str, str] | None:
    norm = normalize_cpe(cpe)
    if not norm:
        return None
    parts = norm.split(":")
    return parts[2], parts[3].lower(), parts[4].lower(), parts[5]

def parse_nmap_services(raw_scan: str, *, max_services: int = 8) -> list[Product]:
    """Parse only completed Nmap XML documents; defuse entities and cap size."""
    products: list[Product] = []
    seen = set()
    for block in _XML_RE.finditer(raw_scan):
        xml = block.group(0)
        if len(xml) > MAX_XML_SIZE:
            continue
        try:
            root = ET.fromstring(xml)
        except (ET.ParseError, DefusedXmlException, ValueError, TypeError):
            continue
        if root.tag != "nmaprun":
            continue
        for host in root.findall("host"):
            for port in host.findall("./ports/port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                service = port.find("service")
                if service is None:
                    continue
                vendor = service.get("product", "").strip()
                version = service.get("version", "").strip()
                protocol, number = port.get("protocol", ""), port.get("portid", "")
                for tag in service.findall("cpe"):
                    cpe = normalize_cpe((tag.text or "").strip())
                    fields = cpe_components(cpe or "")
                    if not cpe or not fields:
                        continue
                    cpe_version = fields[3]
                    if cpe_version not in ("*", "-") and version and cpe_version.casefold() != version.casefold():
                        # Contradicting banner and CPE version: do not query NVD
                        # as though this were a reliable observed version.
                        continue
                    concrete_version = version or (cpe_version if cpe_version not in ("*", "-") else "")
                    if cpe_version in ("*", "-") and not concrete_version:
                        continue
                    # Do not invent version from a textual banner; require a CPE-version
                    # or an explicit Nmap service version, keeping mismatches conservative.
                    if cpe_version in ("*", "-") and concrete_version:
                        parts = cpe.split(":")
                        parts[5] = concrete_version
                        cpe = ":".join(parts)
                    evidence = f"Port {protocol}/{number}: {vendor or fields[2]} {concrete_version} [{cpe}]"
                    key = (cpe, protocol, number)
                    if key not in seen:
                        seen.add(key)
                        products.append(Product(cpe, vendor or fields[2], concrete_version,
                                                f"{number}/{protocol}", service.get("name", ""),
                                                evidence))
                        if len(products) >= max_services:
                            return products
    return products

def parse_explicit_packages(raw_scan: str, *, max_packages: int = 6) -> list[Package]:
    """Only explicit versioned PURLs; never infer ecosystems from banners."""
    result: list[Package] = []
    seen = set()
    for match in _PURL_RE.finditer(raw_scan):
        purl = match.group(0).rstrip(".,);}")
        base = purl.split("?", 1)[0].split("#", 1)[0]
        if "@" not in base:
            continue
        package_path, version = base.rsplit("@", 1)
        kind, _, path = package_path[4:].partition("/")
        kind = kind.lower()
        path = unquote(path)
        version = unquote(version)
        if not path or not version or len(path) > 150 or len(version) > 60:
            continue
        if not re.fullmatch(r"[A-Za-z0-9_.@+\-/%]+", path):
            continue
        if not re.fullmatch(r"[A-Za-z0-9_.+\-]+", version):
            continue
        purl = f"pkg:{kind}/{path}@{version}"
        if purl in seen or kind not in _PURL_TO_OSV:
            continue
        seen.add(purl)
        result.append(Package(purl, _PURL_TO_OSV[kind], path, version))
        if len(result) >= max_packages:
            break
    return result

def github_ecosystem(purl: str) -> str | None:
    kind = purl[4:].split("/", 1)[0].lower()
    return _PURL_TO_GH.get(kind)
