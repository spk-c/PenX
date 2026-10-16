"""OpenAI-compatible local LLM transport (LM Studio, Ollama and llama.cpp)."""

from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit
from collections.abc import Callable
import json
import requests


class ModelConfigurationError(ValueError):
    """Local model selection is missing or ambiguous."""


class EmptyModelResponse(ValueError):
    """An API request succeeded, but did not produce usable assistant text.

    Reasoning tokens are not a final report and must never be executed as
    PenX tool commands or silently substituted for the final answer.
    """

    def __init__(self, *, finish_reason: str = "", reasoning_seen: bool = False,
                 completion_tokens: int | None = None):
        self.finish_reason = str(finish_reason or "unknown")
        self.reasoning_seen = reasoning_seen
        self.completion_tokens = completion_tokens
        details = [f"finish_reason={self.finish_reason}"]
        if reasoning_seen:
            details.append("reasoning tokens without a final answer")
        if completion_tokens is not None:
            details.append(f"completion_tokens={completion_tokens}")
        if self.finish_reason == "length":
            details.append("output token budget exhausted (increase PENX_MAX_TOKENS or disable Qwen thinking)")
        super().__init__("Model returned no assistant answer (" + "; ".join(details) + ").")


class IncompleteModelResponse(EmptyModelResponse):
    """The local model emitted text without successfully completing its answer."""

    def __init__(self, *, completion_tokens: int | None = None, finish_reason: str = "length"):
        super().__init__(finish_reason=finish_reason, completion_tokens=completion_tokens)
        self.args = (
            f"Model response was truncated (finish_reason={finish_reason}). "
            "Incomplete assessments or tool instructions must not be used. "
            + ("Increase PENX_MAX_TOKENS or reduce thinking budget."
               if finish_reason == "length" else "Check the local server's stream completion."),
        )


def explain_http_error(exc: requests.exceptions.HTTPError) -> str:
    """Human-readable local-LLM auth errors without exposing keys or server bodies."""
    response = exc.response
    code = getattr(response, "status_code", None)
    if code == 401:
        return (
            "HTTP 401 Unauthorized: the local LLM endpoint rejected authentication. "
            "Check PENX_LLM_API_KEY in the private .env against the server's --api-key "
            "(or LM Studio authentication setting). Leave it blank only if auth is disabled. "
            "Restart PenX after editing .env; OS environment variables override .env."
        )
    if code == 403:
        return (
            "HTTP 403 Forbidden: the LLM endpoint rejected access. "
            "Check the server's permissions and PENX_LLM_API_KEY in your private .env."
        )
    return f"HTTP {code}: the local LLM request failed." if code else "The local LLM request failed."


def normalize_base_url(value: str) -> str:
    """Accept a server root, /v1 root, or a full chat-completions URL."""
    url = value.strip().rstrip("/")
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.netloc or parts.query or parts.fragment:
        raise ValueError("PENX_LLM_URL must be an HTTP(S) server URL without query parameters.")
    path = parts.path.rstrip("/")
    if path.endswith("/v1/chat/completions"):
        path = path[:-len("/v1/chat/completions")]
    elif path.endswith("/v1"):
        path = path[:-len("/v1")]
    if path.endswith("/v1"):
        path = path[:-len("/v1")]
    return urlunsplit((parts.scheme, parts.netloc, path, "", ""))


def api_headers(api_key: str = "") -> dict:
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    return headers


def fetch_models(models_url: str, api_key: str = "", timeout: int = 5, *,
                 http_get: Callable | None = None) -> list[str]:
    """List model IDs using a caller-supplied client, or the normal local API.

    A call-scoped transport lets offline tests exercise error handling without
    modifying global requests state or making real network calls.
    """
    client = requests.get if http_get is None else http_get
    response = client(models_url, headers=api_headers(api_key), timeout=timeout)
    try:
        response.raise_for_status()
        payload = response.json()
    finally:
        # Release the connection even when HTTP status or JSON parsing fails.
        response.close()
    if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
        raise ValueError("The model endpoint did not return a valid 'data' list.")
    return [item["id"] for item in payload["data"]
            if isinstance(item, dict) and isinstance(item.get("id"), str) and item["id"]]


def resolve_model_name(model_name: str, models_url: str, api_key: str = "", *,
                       model_list: Callable | None = None) -> str:
    """Resolve 'auto' only for a server advertising exactly one model.

    An explicit model ID is never changed or sent through an extra GET request.
    """
    selected = model_name.strip()
    if selected.lower() != "auto":
        if not selected or selected == "your-local-model":
            raise ModelConfigurationError("Set PENX_MODEL to a model ID, or use PENX_MODEL=auto.")
        return selected

    lookup = fetch_models if model_list is None else model_list
    models = lookup(models_url, api_key=api_key)
    if not models:
        raise ModelConfigurationError(
            "No models found at /v1/models. Load a chat-capable model in the LLM server first."
        )
    if len(models) != 1:
        raise ModelConfigurationError(
            "Multiple models available (" + ", ".join(models[:6]) +
            "). Set PENX_MODEL to the intended model ID instead of 'auto'."
        )
    return models[0]


def _plain_text_parts(content: list, *, separator: str = "") -> str:
    """Use explicit final text parts only, never typed reasoning/tool blocks."""
    return separator.join(
        item["text"] for item in content
        if isinstance(item, dict)
        and item.get("type") in (None, "text", "output_text")
        and isinstance(item.get("text"), str)
    )


def extract_chat_text(data: dict) -> str:
    """Read only final assistant content; never promote internal reasoning.

    Some reasoning models return reasoning_content with content=null when
    max_tokens is exhausted. Treating this as a report would produce false
    findings and may execute model-generated tool directives.
    """
    choices = data.get("choices", [])
    if not isinstance(choices, list) or not choices:
        return ""
    choice = choices[0]
    if not isinstance(choice, dict):
        return ""
    message = choice.get("message", {})
    if not isinstance(message, dict):
        return ""
    content = message.get("content")
    if isinstance(content, str):
        return content.strip()
    if isinstance(content, list):
        return _plain_text_parts(content, separator="\n").strip()
    return ""


def _empty_response(data: dict) -> EmptyModelResponse:
    choice = (data.get("choices") or [{}])[0]
    if not isinstance(choice, dict):
        choice = {}
    message = choice.get("message") or {}
    if not isinstance(message, dict):
        message = {}
    usage = data.get("usage") or {}
    if not isinstance(usage, dict):
        usage = {}
    reasoning = bool(message.get("reasoning_content") or message.get("reasoning"))
    details = usage.get("completion_tokens_details") or {}
    if isinstance(details, dict):
        reasoning = reasoning or bool(details.get("reasoning_tokens"))
    total = usage.get("completion_tokens")
    return EmptyModelResponse(
        finish_reason=choice.get("finish_reason") or "",
        reasoning_seen=reasoning,
        completion_tokens=total if isinstance(total, int) else None,
    )


def _validated_chat_payload(data: object) -> dict:
    """Reject malformed provider JSON without exposing raw response bodies."""
    if not isinstance(data, dict) or not isinstance(data.get("choices", []), list):
        raise ValueError("Local LLM returned a malformed chat response.")
    return data


def complete_chat(messages: list, *, url: str, models_url: str, model_name: str,
                  api_key: str = "", max_tokens: int = 8192, timeout: int = 600,
                  temperature: float = 0.7, top_k: int = 10,
                  top_p: float = 0.9, response_format: dict | None = None,
                  stream_callback=None, http_post: Callable | None = None,
                  model_list: Callable | None = None) -> tuple[str, str]:
    """Return model ID and FINAL response text for OpenAI-compatible backends.

    Supports SSE text deltas from llama.cpp, LM Studio and Ollama. Reasoning
    deltas are tracked for diagnostics but never displayed, returned as
    findings or interpreted as tool directives.
    """
    # Keep the old production call signature for existing consumers. Tests and
    # integrations can supply transport ports without patching process globals.
    model_id = (resolve_model_name(model_name, models_url, api_key)
                if model_list is None else resolve_model_name(
                    model_name, models_url, api_key, model_list=model_list))
    post = requests.post if http_post is None else http_post
    stream = stream_callback is not None
    payload = {
        "model": model_id,
        "messages": messages,
        "stream": stream,
        "max_tokens": max_tokens,
        "temperature": temperature,
        "top_k": top_k,
        "top_p": top_p,
    }
    if response_format is not None:
        payload["response_format"] = response_format
    if not stream:
        response = post(url, json=payload, headers=api_headers(api_key), timeout=timeout)
        try:
            response.raise_for_status()
            data = _validated_chat_payload(response.json())
            text = extract_chat_text(data)
            if not text:
                raise _empty_response(data)
            choices = data.get("choices") or []
            if choices and isinstance(choices[0], dict):
                finish = choices[0].get("finish_reason")
                if finish not in (None, "", "stop"):
                    raise IncompleteModelResponse(
                        finish_reason=str(finish),
                        completion_tokens=(data.get("usage") or {}).get("completion_tokens")
                        if isinstance(data.get("usage"), dict) else None,
                    )
            return model_id, text
        finally:
            # The non-stream requests path is not a context manager. Always
            # release its connection, even for malformed or truncated JSON.
            response.close()

    with post(url, json=payload, headers=api_headers(api_key),
              timeout=timeout, stream=True) as response:
        response.raise_for_status()
        if "text/event-stream" not in response.headers.get("content-type", "").lower():
            data = _validated_chat_payload(response.json())
            body = extract_chat_text(data)
            if not body:
                raise _empty_response(data)
            choices = data.get("choices") or []
            if choices and isinstance(choices[0], dict):
                finish = choices[0].get("finish_reason")
                if finish not in (None, "", "stop"):
                    raise IncompleteModelResponse(finish_reason=str(finish))
            stream_callback(body)
            return model_id, body

        parts: list[str] = []
        event: list[str] = []
        reasoning_seen = False
        finish_reason = ""
        done = False
        stream_failed = False
        completion_tokens: int | None = None

        def handle_event(lines: list[str]) -> None:
            nonlocal reasoning_seen, finish_reason, completion_tokens, done, stream_failed
            if any(line.strip() == "event: error" for line in lines):
                stream_failed = True
                return
            for item in lines:
                if not item.startswith("data:"):
                    continue
                value = item[5:].strip()
                if value == "[DONE]":
                    done = True
                    return
                if not value:
                    continue
                try:
                    decoded = json.loads(value)
                    if not isinstance(decoded, dict):
                        # A syntactically valid JSON scalar/list is not an
                        # OpenAI-compatible SSE frame. Do not accept partial
                        # text merely because a later frame says [DONE].
                        stream_failed = True
                        continue
                    # Compatible backends may report failure outside choices,
                    # then emit [DONE]. Never turn their partial text into a report.
                    if "error" in decoded:
                        stream_failed = True
                        continue
                    usage = decoded.get("usage") or {}
                    if isinstance(usage, dict):
                        if isinstance(usage.get("completion_tokens"), int):
                            completion_tokens = usage["completion_tokens"]
                        details = usage.get("completion_tokens_details") or {}
                        if isinstance(details, dict) and details.get("reasoning_tokens"):
                            reasoning_seen = True
                    choices = decoded.get("choices")
                    if choices is None:
                        continue
                    if not isinstance(choices, list):
                        stream_failed = True
                        continue
                    if not choices:
                        # Usage-only streaming frames may have empty choices.
                        continue
                    choice = choices[0]
                    if not isinstance(choice, dict):
                        stream_failed = True
                        continue
                    if choice.get("finish_reason"):
                        finish_reason = str(choice["finish_reason"])
                    delta = choice.get("delta")
                    if delta is None:
                        delta = {}
                    if not isinstance(delta, dict):
                        stream_failed = True
                        continue
                    if delta.get("reasoning_content") or delta.get("reasoning"):
                        reasoning_seen = True
                    content = delta.get("content")
                    if content is None:
                        content = delta.get("text")
                    if isinstance(content, list):
                        # Do not forward provider-typed reasoning/tool blocks to
                        # the streaming callback or completed assessment.
                        content = _plain_text_parts(content)
                    if isinstance(content, str) and content:
                        parts.append(content)
                        stream_callback(content)
                except (ValueError, IndexError, KeyError, TypeError):
                    # Malformed SSE data is not positive completion evidence.
                    stream_failed = True
                    continue

        # SSE data is UTF-8. requests may otherwise decode text/event-stream
        # without a charset as ISO-8859-1, corrupting streamed Unicode before
        # json.loads() and persisting mojibake in assessments and reports.
        for line in response.iter_lines(decode_unicode=False):
            if isinstance(line, bytes):
                line = line.decode("utf-8", errors="replace")
            if not line:
                handle_event(event)
                event = []
                if done:
                    break
            else:
                event.append(line)
        if event:
            handle_event(event)
        final = "".join(parts).strip()
        if stream_failed:
            raise IncompleteModelResponse(completion_tokens=completion_tokens,
                                          finish_reason="error")
        if not final:
            raise EmptyModelResponse(finish_reason=finish_reason,
                                     reasoning_seen=reasoning_seen,
                                     completion_tokens=completion_tokens)
        # Some compatible servers send only [DONE], others only a stop reason.
        # A failure reason takes precedence over [DONE]; plain EOF proves neither.
        if finish_reason != "stop" and not (not finish_reason and done):
            raise IncompleteModelResponse(completion_tokens=completion_tokens,
                                          finish_reason=finish_reason or "missing")
        return model_id, final
