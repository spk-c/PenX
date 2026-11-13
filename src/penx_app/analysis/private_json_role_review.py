"""PX-310: bounded, transient JSON-field presence evidence on loopback lab APIs.

No response bodies/field values are persisted or hashed. Observations are
advisory: a field's presence never proves real data exposure or BOLA/IDOR.
"""
from __future__ import annotations

import re

from penx_app.domain.local_review import strict_json

MAX_JSON_BYTES = 16_384
MAX_POINTERS = 3
MAX_JSON_DEPTH = 12
MAX_JSON_NODES = 200
_SAFE_PART = re.compile(r"[A-Za-z_][A-Za-z0-9_-]{0,47}\Z", re.ASCII)


def validate_pointers(raw: object) -> tuple[str, ...]:
    if not isinstance(raw, list) or not 1 <= len(raw) <= MAX_POINTERS:
        raise ValueError("Select between one and three exact JSON object fields")
    seen: set[str] = set()
    for pointer in raw:
        if (not isinstance(pointer, str) or not 2 <= len(pointer) <= 196
                or not pointer.startswith("/")):
            raise ValueError("Invalid JSON pointer")
        parts = pointer[1:].split("/")
        if not 1 <= len(parts) <= 4 or any(not _SAFE_PART.fullmatch(p) for p in parts):
            raise ValueError("Only literal bounded JSON object keys are supported")
        if pointer in seen:
            raise ValueError("Duplicate protected JSON pointer")
        seen.add(pointer)
    return tuple(raw)


def _bounded_structure(value: object) -> None:
    """Reject oversized/deep/array-heavy JSON without materializing text."""
    total = 0
    stack = [(value, 0)]
    while stack:
        node, depth = stack.pop()
        total += 1
        if total > MAX_JSON_NODES or depth > MAX_JSON_DEPTH:
            raise ValueError("Unbounded JSON structure")
        if isinstance(node, dict):
            stack.extend((v, depth + 1) for v in node.values())
        elif isinstance(node, list):
            stack.extend((v, depth + 1) for v in node)


def _presence(document: dict, pointer: str) -> str:
    current = document
    for part in pointer[1:].split("/"):
        if not isinstance(current, dict) or part not in current:
            return "absent"
        current = current[part]
    if current is None:
        return "null"
    if isinstance(current, (str, list, dict)) and not current:
        return "empty"
    return "present"


def inspect_json_fields(response, pointers: tuple[str, ...]) -> tuple[str, list[dict]]:
    """Read at most 16 KiB of decoded JSON from *one approved 2xx* response.

    Caller is responsible for exact loopback origin, explicit opt-in, session
    closure and never passing non-2xx/redirect responses here. Nothing logs
    raw bytes, values or headers; malformed responses give an inconclusive
    bounded result. The body exists transiently only in this stack frame.
    """
    def result(state: str, fields: list[dict] | None = None):
        return state, fields or []

    try:
        content_type = response.headers.get("Content-Type", "")
        if not isinstance(content_type, str):
            return result("invalid-content-type")
        media = content_type.split(";", 1)[0].strip().lower()
        if media != "application/json" and not media.endswith("+json"):
            return result("not-json")
        length = response.headers.get("Content-Length", "")
        if length:
            if (not isinstance(length, str) or not length.isascii()
                    or not length.isdecimal() or int(length) > MAX_JSON_BYTES):
                return result("oversize-json")
        chunks: list[bytes] = []
        size = 0
        for chunk in response.iter_content(chunk_size=4096):
            if not isinstance(chunk, bytes):
                return result("invalid-json")
            size += len(chunk)
            if size > MAX_JSON_BYTES:
                return result("oversize-json")
            chunks.append(chunk)
        raw = b"".join(chunks)
        document = strict_json(raw.decode("utf-8-sig"))
        if not isinstance(document, dict):
            return result("invalid-json")
        _bounded_structure(document)
        return result("parsed", [
            {"pointer": pointer, "observation": _presence(document, pointer)}
            for pointer in pointers
        ])
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError):
        return result("invalid-json")
