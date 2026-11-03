"""Explicit, bounded metadata-only capability diagnosis of a configured LLM.

No model download or scan-target requests. The optional chat probes use the
existing low-token opt-in compatibility handshake; UNKNOWN != unsupported.
"""
from __future__ import annotations

import ipaddress
import json
from urllib.parse import urlsplit
from collections.abc import Callable

import requests

from penx_app.analysis.llm_client import (
    api_headers, normalize_base_url, probe_model_capabilities,
)

# OpenAI-compatible local servers use several *documented but non-standard*
# context length keys. Only accept finite positive integers from an exact
# matching registry model, never invent capacity from settings or model names.
_CONTEXT_KEYS = ("context_length", "max_context_length", "max_model_len",
                 "n_ctx", "context_window", "num_ctx")
_MAX_MODELS = 128
_MAX_METADATA_BYTES = 512 * 1024


def is_loopback_endpoint(url: str) -> bool:
    hostname = urlsplit(normalize_base_url(url)).hostname
    if hostname == "localhost":
        return True
    try:
        return bool(hostname and ipaddress.ip_address(hostname).is_loopback)
    except ValueError:
        return False


def _positive_integer(value: object) -> int | None:
    if type(value) is int and 1 <= value <= 16_777_216:
        return value
    return None


def parse_model_registry(payload: object, selected_id: str) -> dict:
    """Never confuse model selection with a different served model's metadata."""
    if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
        raise ValueError("Invalid /v1/models response; expected data array.")
    data = payload["data"]
    if len(data) > _MAX_MODELS:
        raise ValueError("Model registry exceeds the supported bounded size.")
    if not isinstance(selected_id, str) or not selected_id or len(selected_id) > 256:
        raise ValueError("Select a nonempty model ID (maximum 256 characters).")
    entries = [row for row in data if isinstance(row, dict)
               and row.get("id") == selected_id]
    if len(entries) > 1:
        raise ValueError("Duplicate selected model IDs in registry.")
    if not entries:
        return {"selected_model": selected_id, "registry_status": "not_listed",
                "context_tokens": None, "context_source": None}
    row = entries[0]
    reported = []
    # Only top-level and the common details object; do not crawl arbitrary
    # nested untrusted metadata or interpret descriptions as capacity.
    nested = row.get("model_info")
    for label, record in (("model", row),
                          ("model_info", nested if isinstance(nested, dict) else {})):
        for key in _CONTEXT_KEYS:
            if key in record:
                value = _positive_integer(record[key])
                if value is not None:
                    reported.append((label + "." + key, value))
    unique = {value for _, value in reported}
    if len(unique) > 1:
        return {"selected_model": selected_id, "registry_status": "listed",
                "context_tokens": None, "context_source": "conflicting_metadata"}
    return {"selected_model": selected_id, "registry_status": "listed",
            "context_tokens": next(iter(unique)) if unique else None,
            "context_source": reported[0][0] if reported else None}


def fetch_model_diagnostics(models_url: str, model_id: str, *,
                            api_key: str = "", timeout: int = 6,
                            http_get: Callable | None = None) -> dict:
    """Read the *configured server's* registry once; never follow redirects."""
    get = requests.get if http_get is None else http_get
    response = get(models_url, headers=api_headers(api_key),
                   timeout=min(max(timeout, 1), 10),
                   allow_redirects=False, stream=True)
    try:
        response.raise_for_status()
        if 300 <= response.status_code < 400:
            raise ValueError("Model registry redirects are not followed.")
        content = response.raw.read(_MAX_METADATA_BYTES + 1, decode_content=True)
        if len(content) > _MAX_METADATA_BYTES:
            raise ValueError("Model registry response too large.")
        return parse_model_registry(json.loads(content), model_id)
    finally:
        response.close()


def diagnostic_report(*, server_url: str, model_id: str, api_key: str = "",
                      probe: bool = False, allow_remote: bool = False,
                      http_get: Callable | None = None,
                      chat: Callable | None = None) -> dict:
    """No outbound call unless explicitly invoked; remote requires extra opt-in."""
    base = normalize_base_url(server_url)
    if not is_loopback_endpoint(base) and not allow_remote:
        raise ValueError("Non-loopback model server requires --allow-remote.")
    if model_id in ("", "your-local-model", "auto"):
        raise ValueError("An explicit model ID is required for diagnostics.")
    models_url = base.rstrip("/") + "/v1/models"
    report = {"selected_model": model_id, "registry_status": "unavailable",
              "context_tokens": None, "context_source": None,
              "chat": "unknown", "streaming": "unknown",
              "json_schema": "unknown", "json_object": "unknown"}
    try:
        report.update(fetch_model_diagnostics(
            models_url, model_id, api_key=api_key, http_get=http_get))
    except (requests.exceptions.RequestException, ValueError, TypeError):
        pass  # A private or unimplemented model registry is not an LLM failure.
    if probe:
        results = probe_model_capabilities(
            url=base.rstrip("/") + "/v1/chat/completions",
            models_url=models_url, model_name=model_id,
            api_key=api_key, timeout=25, chat=chat)
        # The legacy bool handshake distinguishes observed success only.
        # Rejection, timeout, 404 or malformed output must remain UNKNOWN,
        # not claim the model lacks a feature.
        for name in ("chat", "streaming", "json_schema", "json_object"):
            if results.get(name):
                report[name] = "verified"
    return report


def main(argv: list[str], *, settings=None,
         http_get: Callable | None = None,
         chat: Callable | None = None) -> int:
    """Noninteractive, secret-safe model diagnostics; opt-in --probe."""
    import argparse
    from penx_app.app_paths import APP_ROOT
    from penx_app.setup.llm_setup import effective_settings

    parser = argparse.ArgumentParser(prog="penx llm-info")
    parser.add_argument("--probe", action="store_true",
                        help="Send bounded chat/stream/JSON tests to configured model")
    parser.add_argument("--allow-remote", action="store_true",
                        help="Permit sending diagnostics/key to configured non-loopback API")
    try:
        opts = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code) if isinstance(exc.code, int) else 2
    config = settings if settings is not None else effective_settings(APP_ROOT)
    try:
        report = diagnostic_report(
            server_url=config["PENX_LLM_URL"],
            model_id=config["PENX_MODEL"], api_key=config.get("PENX_LLM_API_KEY", ""),
            probe=opts.probe, allow_remote=opts.allow_remote,
            http_get=http_get, chat=chat)
    except (ValueError, requests.exceptions.RequestException) as exc:
        # Server error text may echo API keys; only emit the exception *class*
        # for HTTP failures. Local input validation is safe to display.
        if isinstance(exc, ValueError) and not isinstance(exc, requests.exceptions.RequestException):
            print("LLM diagnostics: " + str(exc))
        else:
            print("LLM diagnostics unavailable (" + type(exc).__name__ + ").")
        return 2
    print(json.dumps(report, ensure_ascii=True, sort_keys=True))
    return 0
