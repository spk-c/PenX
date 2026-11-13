"""PX-309: consent-gated role/status comparison on an exact loopback lab endpoint.

Defensive first slice, not an IDOR exploit or vulnerability verifier. The
operator supplies explicit literal GET paths and a declared role policy.
No OpenAPI route expansion, fuzzing or object-ID replacement. Only explicit
opt-in JSON mode temporarily reads bounded body bytes, never storing values.
"""
from __future__ import annotations

import hashlib
import os
import re
import time
from pathlib import Path
from urllib.parse import urlsplit

import requests

from penx_app.analysis.openapi_contract_map import read_local_contract
from penx_app.analysis.private_json_role_review import inspect_json_fields, validate_pointers
from penx_app.application.browser_preview import BrowserScope
from penx_app.scanners.endpoint_inventory import _safe_probe_path

SCHEMA = "penx-api-role-plan-v1"
REPORT_SCHEMA = "penx-api-role-matrix-v1"
ROLES = ("guest", "user", "admin")
MAX_CASES = 6
MAX_MANIFEST_BYTES = 32_768
_PATH = re.compile(r"/[A-Za-z0-9][A-Za-z0-9._~-]{0,63}(?:/[A-Za-z0-9][A-Za-z0-9._~-]{0,63}){0,4}\Z", re.ASCII)
_TOKEN = re.compile(r"[A-Za-z0-9._~+/\-=]{1,2048}\Z", re.ASCII)


def validate_plan(document: dict) -> tuple[BrowserScope, list[dict]]:
    """Validate all explicit scope/policy metadata BEFORE any HTTP request."""
    if not isinstance(document, dict) or set(document) != {"schema", "origin", "cases"}:
        raise ValueError("Invalid role comparison plan")
    if document["schema"] != SCHEMA:
        raise ValueError("Unsupported role plan schema")
    origin = document["origin"]
    if not isinstance(origin, str) or len(origin) > 256 or "\\" in origin or "%" in origin:
        raise ValueError("Invalid role plan origin")
    parsed = urlsplit(origin)
    # Never resolve hostnames, including localhost, or use LAN/Internet hosts.
    if parsed.hostname not in ("127.0.0.1", "::1") or parsed.path not in ("", "/"):
        raise ValueError("Only a literal loopback origin is permitted")
    scope = BrowserScope.parse(origin)
    if scope.root_path != "/":
        raise ValueError("API role checks require a single exact origin")
    cases = document["cases"]
    if not isinstance(cases, list) or not 1 <= len(cases) <= MAX_CASES:
        raise ValueError("The role plan must contain 1..6 exact GET cases")
    used: set[str] = set()
    output = []
    for case in cases:
        if not isinstance(case, dict) or not {"path", "expect"}.issubset(case) or (
                set(case) - {"path", "expect", "protected_json_pointers"}):
            raise ValueError("Invalid role case")
        path = case["path"]
        if (not isinstance(path, str) or not _PATH.fullmatch(path)
                or not _safe_probe_path(path) or path in used):
            raise ValueError("Unsafe or ambiguous explicit API path")
        expected = case["expect"]
        if (not isinstance(expected, dict) or set(expected) != set(ROLES)
                or any(type(expected[role]) is not str or
                       expected[role] not in ("allow", "deny") for role in ROLES)):
            raise ValueError("Each role needs an explicit allow/deny expectation")
        used.add(path)
        normalized = {"path": path, "expect": dict(expected)}
        if "protected_json_pointers" in case:
            normalized["protected_json_pointers"] = validate_pointers(case["protected_json_pointers"])
        output.append(normalized)
    return scope, output


def load_plan(file_path: str | Path) -> tuple[dict, str]:
    path = Path(file_path)
    # The shared strict local reader also rejects symlinks, duplicate JSON
    # object keys, non-finite numbers and ambiguous UTF-8 input.
    if path.stat().st_size > MAX_MANIFEST_BYTES:
        raise ValueError("API role manifest exceeds 32 KiB")
    document, digest = read_local_contract(path)
    validate_plan(document)
    return document, digest


def _tokens(values: dict | None) -> dict[str, str]:
    if values is None:
        values = {
            "user": os.environ.get("PENX_LAB_USER_TOKEN", ""),
            "admin": os.environ.get("PENX_LAB_ADMIN_TOKEN", ""),
        }
    if not isinstance(values, dict) or set(values) != {"user", "admin"}:
        raise ValueError("Supply exactly two disposable lab role tokens")
    for role in ("user", "admin"):
        value = values[role]
        if not isinstance(value, str) or not _TOKEN.fullmatch(value):
            raise ValueError("Missing or malformed disposable lab role token")
    if values["user"] == values["admin"]:
        raise ValueError("The two lab roles need distinct bearer tokens")
    return dict(values)


def _request_status(url: str, *, role: str, role_tokens: dict, timeout: float,
                    session_factory, protected_pointers: tuple[str, ...] = ()) -> tuple:
    """One GET, one disposable session; optional bounded in-memory JSON read."""

    session = session_factory()
    response = None
    try:
        session.trust_env = False
        session.headers.clear()
        headers = {"Accept": "application/json", "Cache-Control": "no-store"}
        if role != "guest":
            headers["Authorization"] = "Bearer " + role_tokens[role]
        response = session.get(
            url, headers=headers, timeout=(2, timeout), stream=True,
            allow_redirects=False, verify=True)
        status = response.status_code
        if type(status) is not int or not 100 <= status <= 599:
            raise ValueError("Invalid bounded HTTP status")
        if protected_pointers and status == 200:
            try:
                state, fields = inspect_json_fields(response, protected_pointers)
            except requests.RequestException:
                state, fields = "body-read-error", []
            return status, state, fields
        return status, ("not-applicable" if protected_pointers else None), []
    finally:
        if response is not None:
            response.close()
        session.close()


def _compare(expected: str, status: int | None) -> str:
    if status is None or status in (408, 429) or status >= 500:
        return "inconclusive"
    if expected == "deny":
        if status in (401, 403):
            return "matches-declared-policy"
        if 200 <= status <= 299:
            return "possible-excess-access"
        return "inconclusive"
    if 200 <= status <= 299:
        return "matches-declared-policy"
    if status in (401, 403):
        return "unexpected-denial"
    return "inconclusive"


def compare_roles(
    document: dict, *, source_sha256: str, authorized: bool, consent: bool,
    role_tokens: dict | None = None, timeout: int = 5, budget: int = 60,
    session_factory=None, clock=time.monotonic, inspect_json: bool = False,
) -> dict:
    """Execute at most 18 explicitly listed lab GETs with fail-closed results.

    The declared policy is operator-provided, not learned or independently
    proved; status 200 might be a login page. Even suspected excess access
    is only a review lead, NEVER a confirmed BOLA/IDOR/vulnerability.
    """
    scope, cases = validate_plan(document)
    if authorized is not True or consent is not True:
        raise ValueError("Explicit lab ownership and consent are mandatory")
    if type(inspect_json) is not bool:
        raise ValueError("JSON inspection opt-in must be explicit")
    has_pointers = any("protected_json_pointers" in case for case in cases)
    if has_pointers != inspect_json or (
            inspect_json and any("protected_json_pointers" not in case for case in cases)):
        raise ValueError("Explicit --inspect-json requires protected pointers on each case")
    if not isinstance(source_sha256, str) or not re.fullmatch("[0-9a-f]{64}", source_sha256):
        raise ValueError("Plan source fingerprint is invalid")
    if (type(timeout) is not int or not 2 <= timeout <= 20
            or type(budget) is not int or not 10 <= budget <= 120):
        raise ValueError("Invalid HTTP or total request budget")
    role_tokens = _tokens(role_tokens)
    if session_factory is None:
        session_factory = requests.Session

    deadline = clock() + budget
    outcomes = []
    attempted = complete = suspected = unexpected_denials = 0
    protected_json_leads = expected_field_missing = 0
    partial = False
    for case in cases:
        # No variable substitutions or query parameters: exact literal path.
        url = scope.start_url.rstrip("/") + case["path"]
        if not scope.allows(url):
            raise ValueError("An API role case escaped its literal scope")
        observations = []
        for role in ROLES:
            remaining = deadline - clock()
            status = None
            json_state = None
            json_fields: list[dict] = []
            if remaining < 2:
                outcome = "budget-exhausted"
                partial = True
            else:
                attempted += 1
                try:
                    status, json_state, json_fields = _request_status(
                        url, role=role, role_tokens=role_tokens,
                        timeout=min(timeout, remaining), session_factory=session_factory,
                        protected_pointers=case.get("protected_json_pointers", ()))
                    complete += 1
                    outcome = _compare(case["expect"][role], status)
                    if inspect_json and 200 <= status <= 299:
                        if json_state != "parsed":
                            partial = True
                        elif case["expect"][role] == "deny" and any(
                                field["observation"] == "present" for field in json_fields):
                            protected_json_leads += 1
                        elif case["expect"][role] == "allow" and not any(
                                field["observation"] == "present" for field in json_fields):
                            expected_field_missing += 1
                except (requests.RequestException, OSError, ValueError):
                    outcome = "transport-error"
                if outcome in {"transport-error", "inconclusive"}:
                    partial = True
            if outcome == "possible-excess-access":
                suspected += 1
            if outcome == "unexpected-denial":
                unexpected_denials += 1
            row = {
                "role": role, "expected": case["expect"][role],
                "http_status": status, "comparison": outcome,
            }
            if inspect_json:
                row["json_inspection"] = {
                    "state": (json_state if json_state is not None else
                              "not-inspected"),
                    "protected_fields": json_fields,
                }
            observations.append(row)
        outcomes.append({"path": case["path"], "method": "GET", "roles": observations})

    report = {
        "schema": REPORT_SCHEMA if not inspect_json else "penx-api-role-matrix-json-v1",
        "state": ("local-lab-status-comparison-unverified" if not inspect_json
                  else "local-lab-json-presence-comparison-unverified"),
        "coverage": "PARTIAL" if partial else "COMPLETE",
        "plan_sha256": source_sha256,
        "origin_sha256": hashlib.sha256(scope.start_url.encode("ascii")).hexdigest(),
        "tested_path_count": len(cases),
        "attempted_requests": attempted,
        "status_responses": complete,
        "suspected_excess_access": suspected,
        "unexpected_denials": unexpected_denials,
        "vulnerability_verified": False,
        "bola_idor_verified": False,
        "response_bodies_collected": False,
        "scan_grant_transferable": False,
        "cases": outcomes,
        "limitations": (
            "Only exact, manually selected, disposable loopback GET tests. "
            "The expected policy comes from the operator, not an authority. "
            "Status codes do not prove returned data, authorization failures, "
            "vulnerability presence, exploitability or lack of risk. "
            "No payloads, response bodies, authentication tokens or session "
            "cookies are saved; a possible mismatch requires human review."
        ),
    }
    if inspect_json:
        report.update({
            "json_inspection_enabled": True,
            "protected_json_presence_leads": protected_json_leads,
            "allow_role_expected_fields_missing": expected_field_missing,
            "response_bodies_inspected_transiently": True,
            "raw_json_values_persisted": False,
            "limitations": (
                report["limitations"] +
                " Selected JSON object fields are checked transiently under "
                "a 16 KiB decompressed body limit; values/hashes/raw bodies "
                "are never persisted. A present field may be generic or "
                "non-sensitive and is not evidence of cross-user disclosure."
            ),
        })
    return report
