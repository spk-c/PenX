"""Versioned finding identity independent of storage IDs and assessment severity."""
from __future__ import annotations

import hashlib
import json
import unicodedata
from urllib.parse import urlsplit, urlunsplit


def canonical_target(target: str) -> str:
    """Normalize host spelling without aliasing case-sensitive URL scopes."""
    value = str(target).strip()
    if '://' in value:
        try:
            parts = urlsplit(value)
        except ValueError:
            return value
        userinfo, delimiter, authority = parts.netloc.rpartition('@')
        return urlunsplit((parts.scheme.lower(), userinfo + delimiter + authority.lower(),
                           '' if parts.path == '/' else parts.path,
                           parts.query, parts.fragment))
    host, separator, path = value.partition('/')
    return host.lower() + (separator + path if path else '')


def finding_fingerprint(name: str, port: str, service: str, *, target: str,
                        case_sensitive_name: bool = False) -> str:
    """Conservative exact identity: never merge renamed vulnerability claims.

    Session IDs, dates, evidence wording, confidence and severity can change
    without changing identity. Scope remains part of identity. Only Unicode,
    case and whitespace are normalized for labels, not URL paths/query values.
    Scanner rule identifiers can opt into case-sensitive name matching.
    """
    def normalize(value: str) -> str:
        return " ".join(unicodedata.normalize("NFC", str(value or "")).casefold().split())

    def scope(value: str) -> str:
        raw = str(value or '').strip()
        if '://' in raw:
            return canonical_target(raw)
        if raw.startswith(('/', '+ /')):
            return raw  # Relative endpoint paths, including Nikto labels.
        return normalize(raw)

    identity_name = unicodedata.normalize('NFC', str(name or '').strip()) if case_sensitive_name else normalize(name)
    content = [scope(canonical_target(target)), identity_name, scope(port), normalize(service)]
    encoded = json.dumps(content, ensure_ascii=True, separators=(",", ":"))
    return "penx-finding-v1:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()
