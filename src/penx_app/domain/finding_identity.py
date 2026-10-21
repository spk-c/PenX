"""Versioned finding identity independent of storage IDs and assessment severity."""
from __future__ import annotations

import hashlib
import json
import unicodedata


def finding_fingerprint(name: str, port: str, service: str, *, target: str) -> str:
    """Conservative exact identity: never merge renamed vulnerability claims.

    Session IDs, dates, evidence wording, confidence and severity can change
    without changing identity. Scope remains part of identity. Only Unicode,
    case and whitespace are normalized; URLs and port scopes are not guessed.
    """
    def normalize(value: str) -> str:
        return " ".join(unicodedata.normalize("NFC", str(value or "")).casefold().split())

    content = [normalize(value) for value in (target, name, port, service)]
    encoded = json.dumps(content, ensure_ascii=True, separators=(",", ":"))
    return "penx-finding-v1:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()
