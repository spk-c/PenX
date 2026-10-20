"""Interactive first-run local LLM setup for PenX's terminal interface.

Runs before config.py is imported, so settings take effect immediately on first
launch. Does not download models, execute scanners, or silently install software.
"""
from __future__ import annotations

import getpass
import os
from pathlib import Path
import re
import sys
import tempfile
from urllib.parse import urlsplit

from dotenv import dotenv_values
import requests

from penx_app.app_paths import APP_ROOT
from penx_app.analysis.llm_client import (complete_chat, explain_http_error,
    fetch_models, normalize_base_url, probe_model_capabilities)

_BACKENDS = (
    ("LM Studio", "http://127.0.0.1:1234"),
    ("Ollama", "http://127.0.0.1:11434"),
    ("llama.cpp / llama-server", "http://127.0.0.1:8080"),
    ("Other OpenAI-compatible API", "http://127.0.0.1:1234"),
    ("Discover running local API", ""),
)

# Fixed loopback endpoints only. Ports are hints, not provider fingerprints.
_DISCOVERY_ENDPOINTS = (
    ("LM Studio (typical port)", "http://127.0.0.1:1234"),
    ("llama.cpp / NInfer / LocalAI (typical port)", "http://127.0.0.1:8080"),
    ("Ollama (typical port)", "http://127.0.0.1:11434"),
    ("vLLM (typical port)", "http://127.0.0.1:8000"),
    ("SGLang (typical port)", "http://127.0.0.1:30000"),
    ("TabbyAPI (typical port)", "http://127.0.0.1:5000"),
    ("KoboldCpp (typical port)", "http://127.0.0.1:5001"),
)
_KEYS = ("PENX_LLM_URL", "PENX_MODEL", "PENX_LLM_API_KEY")


def effective_settings(root: Path = APP_ROOT) -> dict[str, str]:
    """Respect process environment > .env and legacy METATRON_* settings."""
    file_values = dotenv_values(root / ".env") if (root / ".env").is_file() else {}
    result = {}
    for suffix in ("LLM_URL", "MODEL", "LLM_API_KEY"):
        key = "PENX_" + suffix
        fallback = "METATRON_" + suffix
        result[key] = (os.environ.get(key, os.environ.get(fallback,
                       file_values.get(key) or file_values.get(fallback) or "")) or "").strip()
    return result


def needs_setup(root: Path = APP_ROOT) -> bool:
    settings = effective_settings(root)
    url = settings["PENX_LLM_URL"]
    model = settings["PENX_MODEL"]
    if not url or not model or model.lower() == "your-local-model":
        return True
    try:
        return not bool(urlsplit(normalize_base_url(url)).hostname)
    except ValueError:
        return True


def _ask(message: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    answer = input(f"{message}{suffix}: ").strip()
    if answer.lower() in ("q", "quit", "cancel"):
        raise KeyboardInterrupt
    return answer or default


def _yes(message: str, *, default: bool = False) -> bool:
    response = _ask(message + (" [Y/n]" if default else " [y/N]")).lower()
    return response in ("y", "yes") or (not response and default)


def _url(value: str) -> str:
    cleaned = normalize_base_url(value)
    parts = urlsplit(cleaned)
    if not parts.hostname or parts.username or parts.password or any(c.isspace() for c in cleaned):
        raise ValueError("Enter a complete HTTP(S) URL without embedded credentials or spaces.")
    return cleaned


def _quote(value: str) -> str:
    if "\r" in value or "\n" in value or "\x00" in value:
        raise ValueError("Configuration values cannot contain line breaks or NUL bytes.")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def save_settings(root: Path, *, url: str, model: str, api_key: str) -> Path:
    """Atomically replace only the LLM keys; preserve other .env settings.

    Never use os.environ as a store; dotenv is read later by config.py.
    """
    target = root / ".env"
    template = root / ".env.example"
    if target.is_file():
        old = target.read_text(encoding="utf-8")
    elif template.is_file():
        old = template.read_text(encoding="utf-8")
    else:
        old = "# Private PenX configuration\n"
    values = {"PENX_LLM_URL": _url(url), "PENX_MODEL": model.strip(),
              "PENX_LLM_API_KEY": api_key}
    if not values["PENX_MODEL"] or values["PENX_MODEL"] == "your-local-model":
        raise ValueError("A real model ID must be selected.")
    replacements = {key: f"{key}={_quote(value)}" for key, value in values.items()}
    output, found = [], set()
    for line in old.splitlines(keepends=True):
        match = re.match(r"^\s*(?:export\s+)?(PENX_LLM_URL|PENX_MODEL|PENX_LLM_API_KEY)\s*=", line)
        if not match:
            output.append(line)
            continue
        key = match.group(1)
        if key not in found:
            output.append(replacements[key] + ("\r\n" if line.endswith("\r\n") else "\n"))
            found.add(key)
        # Ignore duplicate assignments: do not leave a later value overriding the chosen one.
    content = "".join(output)
    if content and not content.endswith(("\n", "\r")):
        content += "\n"
    for key in _KEYS:
        if key not in found:
            content += replacements[key] + "\n"
    root.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".penx-env-", dir=root)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(content)
        if os.name != "nt":
            os.chmod(tmp, 0o600)
        os.replace(tmp, target)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    return target



def discover_local_backends(*, list_models=None) -> list[tuple[str, str, list[str]]]:
    """Find model APIs on known localhost ports without scanning the LAN.

    This is endpoint discovery, not authoritative provider identification. An
    authenticated server may need manual configuration (menu option 4).
    """
    lookup = fetch_models if list_models is None else list_models
    found = []
    for hint, base in _DISCOVERY_ENDPOINTS:
        try:
            models = lookup(base + "/v1/models", timeout=2)
        except (requests.exceptions.RequestException, ValueError):
            continue
        if models:
            found.append((hint, base, models))
    return found


def setup_wizard(root: Path = APP_ROOT) -> bool:
    """Run the whole wizard; caller handles cancellation and noninteractive cases."""
    existing = effective_settings(root)
    print("\n" + "=" * 58)
    print("  PenX | LOCAL AI SETUP")
    print("=" * 58)
    print("Start your local model server and load a chat-capable model first.")
    print("No models will be downloaded, and no target will be scanned.")
    print("Enter q at a prompt to cancel without saving.\n")
    env_overrides = [key for key in _KEYS if key in os.environ or
                     key.replace("PENX_", "METATRON_") in os.environ]
    if env_overrides:
        print("[WARN] OS environment overrides .env: " + ", ".join(env_overrides))
        print("       Remove those overrides if the saved configuration is ignored.")

    while True:
        print("\nSelect local LLM backend:")
        for n, (label, default_url) in enumerate(_BACKENDS, 1):
            print(f"  [{n}] {label}  ({default_url})")
        choice = _ask("Backend 1-5", "1")
        if choice not in ("1", "2", "3", "4", "5"):
            print("[WARN] Select 1, 2, 3, 4 or 5.")
            continue
        if choice == "5":
            print("[*] Checking known localhost model API ports (no network scan)...")
            detected = discover_local_backends()
            if not detected:
                print("[WARN] No unauthenticated local models found. Try option 4.")
                continue
            for index, (hint, base, models) in enumerate(detected, 1):
                print(f"  [{index}] {base} — {hint} ({len(models)} model(s))")
            selected = _ask("Choose detected endpoint", "1")
            if not selected.isdigit() or not 1 <= int(selected) <= len(detected):
                print("[WARN] Invalid detected endpoint.")
                continue
            default = detected[int(selected) - 1][1]
        else:
            default = _BACKENDS[int(choice) - 1][1]
        entered_url = (existing["PENX_LLM_URL"] if choice == "4" and existing["PENX_LLM_URL"]
                       else default)
        while True:
            try:
                base = _url(_ask("Local API server URL", entered_url))
                break
            except ValueError as exc:
                print("[WARN] " + str(exc))
        hostname = urlsplit(base).hostname
        if hostname not in ("localhost", "127.0.0.1", "::1"):
            print("[WARN] Non-loopback endpoint: assessment data and API keys can leave this PC.")
            if not _yes("Use this address anyway?", default=False):
                continue

        has_saved_key = bool(existing["PENX_LLM_API_KEY"])
        require_key = _yes("Is API key authentication enabled?", default=has_saved_key)
        key = ""
        if require_key:
            key = getpass.getpass(
                "API key (hidden" + (", Enter keeps current key" if has_saved_key else "") + "): "
            ).strip()
            if not key and has_saved_key:
                key = existing["PENX_LLM_API_KEY"]
            if not key:
                print("[WARN] A key is required when authentication is enabled.")
                continue

        models = []
        try:
            print("\n[*] Fetching available models from " + base + "/v1/models ...")
            models = fetch_models(base + "/v1/models", api_key=key, timeout=6)
        except requests.exceptions.HTTPError as exc:
            print("[WARN] " + explain_http_error(exc))
        except (requests.exceptions.RequestException, ValueError) as exc:
            print(f"[WARN] Model listing unavailable ({type(exc).__name__}).")
        if models:
            print("Available model IDs:")
            for i, model_id in enumerate(models, 1):
                print(f"  [{i}] {model_id}")
            print("  [m] Enter model ID manually")
            while True:
                selected = _ask("Select model", "1")
                if selected.isdigit() and 1 <= int(selected) <= len(models):
                    model = models[int(selected) - 1]
                    break
                if selected.lower() == "m":
                    model = _ask("Exact model ID")
                    if model:
                        break
                print("[WARN] Choose a listed number or m.")
        else:
            print("[INFO] If the server is offline or hides /v1/models,")
            print("       you can enter the exact model ID manually.")
            model = _ask("Exact model ID", existing["PENX_MODEL"]
                         if existing["PENX_MODEL"] != "your-local-model" else "")
            if not model:
                print("[WARN] No model selected. Recheck your server details.")
                continue

        print("\nSelected endpoint: " + base)
        print("Selected model: " + model)
        print("API key: " + ("configured (hidden)" if key else "not required"))
        tested = False
        if _yes("Send a short test request to the selected model?", default=True):
            try:
                resolved, answer = complete_chat(
                    [{"role": "user", "content": "Reply with the single word OK."}],
                    url=base + "/v1/chat/completions", models_url=base + "/v1/models",
                    model_name=model, api_key=key, max_tokens=24, timeout=35,
                    top_k=1, temperature=0.0,
                )
                if not answer:
                    print("[WARN] Model returned no text.")
                else:
                    tested = True
                    print("[OK] AI responded via " + resolved)
                    print("[*] Checking streaming and structured output...")
                    capabilities = probe_model_capabilities(
                        url=base + "/v1/chat/completions",
                        models_url=base + "/v1/models", model_name=model,
                        api_key=key, chat=complete_chat)
                    for name in ("streaming", "json_schema", "json_object"):
                        state = "OK" if capabilities[name] else "unverified/unavailable"
                        print(f"  {name}: {state}")
                    if not (capabilities["json_schema"] or capabilities["json_object"]):
                        print("[INFO] PENX_STRUCTURED_OUTPUT=auto can use legacy text fallback.")
            except requests.exceptions.HTTPError as exc:
                print("[WARN] " + explain_http_error(exc))
            except (requests.exceptions.RequestException, ValueError) as exc:
                print(f"[WARN] Model test failed ({type(exc).__name__}).")
        if not tested:
            print("[WARN] The selected model has NOT been verified.")
            if not _yes("Save these settings despite the unverified model?", default=False):
                if _yes("Change settings and retry?", default=True):
                    continue
                return False
        if not _yes("Save local LLM configuration to the private .env?", default=True):
            return False
        path = save_settings(root, url=base, model=model, api_key=key)
        print("[OK] Local LLM configuration saved to: " + str(path))
        print("[INFO] API secrets are not printed; keep your .env private.")
        return True


def maybe_configure_llm(root: Path = APP_ROOT, *, force: bool = False,
                        interactive: bool | None = None) -> bool:
    """Auto-start only for missing/placeholder config in an interactive terminal."""
    if not force and not needs_setup(root):
        return False
    if interactive is None:
        interactive = sys.stdin.isatty()
    if not interactive:
        print("[INFO] Local LLM is not configured; run PenX with a terminal or use --llm-setup.")
        return False
    try:
        return setup_wizard(root)
    except (KeyboardInterrupt, EOFError):
        print("\n[INFO] Local AI setup cancelled; no settings changed.")
        return False
    except OSError as exc:
        print("[WARN] Could not save local AI configuration: " + str(exc))
        return False
