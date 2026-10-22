"""One bounded local-only request with no proxy, redirects, tools or retries."""
from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit, urlunsplit

import requests

from penx_app.analysis.llm_client import api_headers, extract_chat_text, normalize_base_url
from penx_app.domain.local_review import MAX_RESPONSE_BYTES, strict_json


def local_endpoint(value: str) -> str:
    base = normalize_base_url(value)
    parts = urlsplit(base)
    host = parts.hostname
    if host == 'localhost':
        host = '127.0.0.1'
    try:
        address = ipaddress.ip_address(host or '')
    except ValueError:
        raise ValueError('Review endpoint must be a literal loopback IP or localhost') from None
    if not address.is_loopback:
        raise ValueError('Review endpoint must be local; remote/cloud endpoints are unsupported')
    authority = f'[{address}]' if address.version == 6 else str(address)
    if parts.port is not None:
        authority += ':' + str(parts.port)
    return urlunsplit((parts.scheme, authority, parts.path.rstrip('/') + '/v1/chat/completions', '', ''))


def validate_review_options(model: str, timeout: int) -> str:
    """Validate before request admission or an injected client is invoked."""
    if not isinstance(model, str):
        raise ValueError('Choose an explicit local model ID; discovery is disabled')
    model = model.strip()
    if not model or len(model) > 200 or model.casefold() == 'auto':
        raise ValueError('Choose an explicit local model ID; discovery is disabled')
    if type(timeout) is not int or not 5 <= timeout <= 120:
        raise ValueError('Review read timeout must be in 5..120 seconds')
    return model


def request_review(messages: list[dict], *, endpoint: str, model: str, schema: dict,
                   api_key: str = '', timeout: int = 60, session_factory=None) -> str:
    endpoint = local_endpoint(endpoint)
    model = validate_review_options(model, timeout)
    factory = requests.Session if session_factory is None else session_factory
    with factory() as session:
        session.trust_env = False
        with session.post(endpoint, headers=api_headers(api_key),
                          json={'model': model, 'messages': messages, 'stream': False,
                                'temperature': 0, 'max_tokens': 2048,
                                'response_format': {'type': 'json_schema', 'json_schema': {
                                    'name': 'penx_review', 'strict': True, 'schema': schema}}},
                          timeout=(5, timeout), allow_redirects=False, stream=True) as response:
            if not 200 <= response.status_code < 300:
                raise ValueError('Local review server rejected the request')
            content = bytearray()
            for chunk in response.iter_content(chunk_size=4096):
                if len(content) + len(chunk) > MAX_RESPONSE_BYTES:
                    raise ValueError('Local review response exceeds 64 KiB')
                content.extend(chunk)
            payload = strict_json(content.decode('utf-8'))
    if not isinstance(payload, dict) or 'error' in payload:
        raise ValueError('Invalid local model response')
    choices = payload.get('choices')
    if not isinstance(choices, list) or len(choices) != 1 or not isinstance(choices[0], dict):
        raise ValueError('Review requires one completed assistant answer')
    choice = choices[0]
    message = choice.get('message')
    if (choice.get('finish_reason') != 'stop' or not isinstance(message, dict)
            or message.get('role') != 'assistant'
            or message.get('refusal')
            or message.get('tool_calls') or message.get('function_call')):
        raise ValueError('Incomplete or tool-bearing local review rejected')
    text = extract_chat_text(payload)
    if not text:
        raise ValueError('Local model returned no final answer')
    return text
