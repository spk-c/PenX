# Local model capability diagnostics (PX-401)

PenX already offers an interactive `--llm-setup` wizard with an opt-in chat,
streaming and structured-JSON handshake. The noninteractive `llm-info`
command adds a read-only model registry diagnostic:

```text
python penx.py llm-info
python penx.py llm-info --probe
python penx.py llm-info --probe --allow-remote
```

The command reads `PENX_LLM_URL`, `PENX_MODEL` and optional
`PENX_LLM_API_KEY` from environment or .env (process overrides win).
It does not save settings, download models, scan assessment targets,
auto-discover ports, or send chat requests unless `--probe` is given.

Only loopback servers are allowed by default; `--allow-remote` is
required for a configured non-loopback endpoint. Remote endpoints can
receive the configured secret and short fixture prompts; use this option
only for servers you control and trust. Registry requests have a 6-second
timeout, 512 KiB decompressed response cap, 128 model-entry limit, and
redirects are never followed.

Output is one JSON object with selected model ID, registry status (listed,
not_listed or unavailable), context_tokens/context_source, and optional
chat, streaming, json_schema and json_object capability values.
Capability values are verified or unknown; an HTTP error, timeout,
bad JSON, or missing endpoint does not prove a feature unsupported.

A context window is reported only when the exact selected model entry
contains an unambiguous positive integer in a recognized field. Conflicting
fields are explicitly marked and do not produce a guessed context length.
A missing field is unknown, not zero. Selected model ID is not proof of
the actual loaded model weights. Context retention, provider cancellation,
quality and speed are not attested.

Deterministic tests use injected transports, no real model or external
host. Live NInfer/Strata/llama.cpp/Ollama field validation is separate.
This is a partial PX-401 implementation, not a full field sign-off or release.
