"""Offline OpenAPI 3.x contract inventory; declarations are NOT observed endpoints.

PX-308: no network, model, scanner, dereferencing, credentials, examples,
request bodies, response payloads, or authorization grants. The output is
bounded structural metadata for later human-approved API assessment planning.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import stat
from typing import Any

from penx_app.domain.local_review import strict_json

SCHEMA = "penx-openapi-contract-map-v1"
MAX_FILE_BYTES = 1_048_576
MAX_INPUT_PATHS = 300
MAX_OUTPUT_PATHS = 150
MAX_PARAMETERS = 32
MAX_SECURITY_ALTERNATIVES = 16
METHODS = ("get", "head", "options", "post", "put", "patch", "delete", "trace")
METHOD_NAMES = set(METHODS)
PATH_METADATA = {"summary", "description", "parameters", "servers", "$ref"}
PATH_PATTERN = re.compile(r"/(?:(?:[A-Za-z0-9._~-]+)|(?:\{[A-Za-z_][A-Za-z0-9_]{0,63}\}))(?:/(?:(?:[A-Za-z0-9._~-]+)|(?:\{[A-Za-z_][A-Za-z0-9_]{0,63}\})))*/*\Z", re.ASCII)
PARAM_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}\Z", re.ASCII)
SPEC_VERSION = re.compile(r"3\.(?:0|1)\.[0-9]{1,2}\Z", re.ASCII)
SECURITY_TYPES = {"apiKey", "http", "oauth2", "openIdConnect", "mutualTLS"}


def read_local_contract(file_path: str | Path) -> tuple[dict, str]:
    """Refuse symlink swaps and unbounded/duplicate/nonfinite JSON documents."""
    path = Path(file_path)
    if path.is_symlink():
        raise ValueError("OpenAPI input must be a regular file, not a link")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        opened, named = os.fstat(stream.fileno()), path.lstat()
        if (not stat.S_ISREG(opened.st_mode) or not stat.S_ISREG(named.st_mode)
                or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
                or opened.st_size > MAX_FILE_BYTES):
            raise ValueError("OpenAPI input must be an ordinary file at most 1 MiB")
        raw = stream.read(MAX_FILE_BYTES + 1)
    if len(raw) > MAX_FILE_BYTES:
        raise ValueError("OpenAPI input exceeds 1 MiB")
    try:
        document = strict_json(raw.decode("utf-8-sig"))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ValueError("Invalid or ambiguous OpenAPI JSON") from exc
    if not isinstance(document, dict):
        raise ValueError("OpenAPI root must be an object")
    return document, hashlib.sha256(raw).hexdigest()


def _contract_path(path: Any) -> str:
    """Conservative template-path grammar; never decode or normalize escapes."""
    if not isinstance(path, str) or len(path) > 256:
        raise ValueError("Invalid API contract path")
    if path == "/":
        return path
    if (not PATH_PATTERN.fullmatch(path) or "//" in path
            or any(segment in (".", "..") for segment in path.split("/"))):
        raise ValueError("Unsafe or ambiguous API contract path")
    return path


def _parameter_names(parameters: Any) -> tuple[set[str], set[str], bool]:
    """Retain only path/query names, never header/cookie values or examples."""
    if parameters is None:
        return set(), set(), False
    if not isinstance(parameters, list) or len(parameters) > MAX_PARAMETERS:
        raise ValueError("Invalid bounded parameter declarations")
    path_names: set[str] = set()
    query_names: set[str] = set()
    unresolved = False
    for param in parameters:
        if not isinstance(param, dict):
            raise ValueError("Invalid parameter entry")
        if "$ref" in param:
            unresolved = True  # Never fetch or resolve external/local ref.
            continue
        name = param.get("name")
        place = param.get("in")
        if not isinstance(name, str) or not PARAM_PATTERN.fullmatch(name):
            raise ValueError("Invalid parameter name")
        if place not in ("query", "path", "header", "cookie"):
            raise ValueError("Invalid parameter location")
        if place == "query":
            query_names.add(name)
        elif place == "path":
            path_names.add(name)
    return path_names, query_names, unresolved


def _security(
    alternatives: Any, schemes: dict | None,
) -> tuple[str, list[str]]:
    """Interpret *declared* auth alternatives, not verified access control."""
    if alternatives is None:
        return "unspecified", []
    if (not isinstance(alternatives, list)
            or len(alternatives) > MAX_SECURITY_ALTERNATIVES):
        raise ValueError("Invalid security declaration")
    if not alternatives:
        return "none-declared", []
    types: set[str] = set()
    unresolved = False
    has_anonymous_alternative = False
    for alternative in alternatives:
        if not isinstance(alternative, dict) or len(alternative) > 16:
            raise ValueError("Invalid security alternative")
        if not alternative:
            has_anonymous_alternative = True
        for scheme_name, scopes in alternative.items():
            if (not isinstance(scheme_name, str) or len(scheme_name) > 128
                    or not isinstance(scopes, list) or len(scopes) > 32
                    or not all(isinstance(scope, str) and len(scope) <= 128
                               for scope in scopes)):
                raise ValueError("Invalid security scopes")
            item = schemes.get(scheme_name) if schemes is not None else None
            if not isinstance(item, dict) or "$ref" in item:
                unresolved = True
                continue
            declared = item.get("type")
            if not isinstance(declared, str) or declared not in SECURITY_TYPES:
                unresolved = True
                continue
            types.add(declared)
    if has_anonymous_alternative:
        return "none-declared", []
    return ("unresolved" if unresolved else "auth-declared"), sorted(types)


def build_contract_map(document: dict, *, source_sha256: str) -> dict:
    """Build a source-pinned offline map, never an actionable scanner plan."""
    if not isinstance(document, dict) or not SPEC_VERSION.fullmatch(str(document.get("openapi", ""))):
        raise ValueError("Only OpenAPI 3.0.x/3.1.x JSON is supported")
    if not isinstance(source_sha256, str) or not re.fullmatch("[0-9a-f]{64}", source_sha256):
        raise ValueError("Source hash must be pinned to exact input bytes")
    paths = document.get("paths")
    if not isinstance(paths, dict) or len(paths) > MAX_INPUT_PATHS:
        raise ValueError("Invalid or unbounded OpenAPI paths object")

    components = document.get("components", {})
    if not isinstance(components, dict):
        raise ValueError("Invalid components object")
    schemes = components.get("securitySchemes", {})
    if not isinstance(schemes, dict) or len(schemes) > 64:
        raise ValueError("Invalid security schemes object")
    server_declarations = document.get("servers", [])
    if not isinstance(server_declarations, list) or len(server_declarations) > 32:
        raise ValueError("Invalid servers list")
    root_security = document.get("security")
    # Validate root auth even when every operation overrides it.
    _security(root_security, schemes)

    rows: list[dict] = []
    unresolved_refs = invalid_extensions = 0
    operation_count = 0
    for path, value in sorted(paths.items()):
        path = _contract_path(path)
        if not isinstance(value, dict):
            raise ValueError("Invalid OpenAPI path item")
        if "$ref" in value:
            unresolved_refs += 1
            continue
        unknown = [key for key in value if key not in PATH_METADATA
                   and key not in METHOD_NAMES and not key.startswith("x-")]
        if unknown:
            invalid_extensions += len(unknown)
        path_names, path_query, path_unresolved = _parameter_names(value.get("parameters"))
        for method in METHODS:
            operation = value.get(method)
            if operation is None:
                continue
            if not isinstance(operation, dict):
                raise ValueError("Invalid OpenAPI operation")
            if "$ref" in operation:
                unresolved_refs += 1
                continue
            deprecated = operation.get("deprecated", False)
            if type(deprecated) is not bool:
                raise ValueError("Invalid deprecated flag")
            op_paths, op_query, op_unresolved = _parameter_names(operation.get("parameters"))
            all_query = sorted(path_query | op_query)
            all_path = sorted(path_names | op_paths)
            # OpenAPI template path parameter names are safe metadata only.
            template_names = set(re.findall(r"\{([A-Za-z_][A-Za-z0-9_]{0,63})\}", path))
            all_path = sorted(set(all_path) | template_names)
            if len(all_query) > MAX_PARAMETERS or len(all_path) > MAX_PARAMETERS:
                raise ValueError("Combined parameter budget exceeded")
            status, scheme_types = _security(operation.get("security", root_security), schemes)
            unresolved = path_unresolved or op_unresolved or status == "unresolved"
            if unresolved:
                unresolved_refs += 1
            operation_count += 1
            rows.append({
                "path_template": path,
                "method": method.upper(),
                "deprecated": deprecated,
                "path_parameters": all_path,
                "query_parameters": all_query,
                "auth": status,
                "auth_types_declared": scheme_types,
                "referenced_metadata_incomplete": bool(unresolved),
                "source": "openapi-declaration-not-observed",
                "request_performed": False,
            })
    # Soft output cap keeps every operation from the first N paths together.
    eligible_paths = sorted({item["path_template"] for item in rows})
    allowed_paths = set(eligible_paths[:MAX_OUTPUT_PATHS])
    rows = [item for item in rows if item["path_template"] in allowed_paths]
    truncated = max(0, len(eligible_paths) - len(allowed_paths))
    incomplete = bool(unresolved_refs or invalid_extensions or truncated)
    return {
        "schema": SCHEMA,
        "state": "offline-declared-not-verified",
        "coverage": "PARTIAL" if incomplete or not rows else "COMPLETE",
        "source_sha256": source_sha256,
        "openapi_version": document["openapi"],
        "server_entries_ignored": len(server_declarations),
        "declared_paths": len(paths),
        "declared_operations": operation_count,
        "mapped_operations": len(rows),
        "unresolved_reference_items": unresolved_refs,
        "unknown_path_fields": invalid_extensions,
        "truncated_paths": truncated,
        "endpoints": rows,
        "network_requests": 0,
        "vulnerability_verified": False,
        "scan_authorized": False,
        "limitations": (
            "OpenAPI declarations are untrusted metadata, NOT observed routes or grants. "
            "No server URL, authentication material, examples, payloads, external refs "
            "or operations were fetched or executed. COMPLETE means structural mapping "
            "of supported fields only, never endpoint security or availability."
        ),
    }
