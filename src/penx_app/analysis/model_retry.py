"""Pure, bounded retry planner for a local model's empty assistant response."""
from __future__ import annotations


def prepare_empty_retry(messages: list, max_tokens: int,
                        configured_tokens: str) -> tuple[list, int]:
    """Copy messages; never read global config or perform HTTP/terminal I/O."""
    retry_messages = [dict(message) for message in messages]
    if retry_messages and retry_messages[-1].get("role") == "user":
        last = retry_messages[-1]
        if isinstance(last.get("content"), str):
            last["content"] += (
                "\n\n/no_think\n"
                "Respond directly with the requested assessment. "
                "Do not spend output tokens on internal reasoning. "
                "Keep any [TOOL:] or [SEARCH:] requests scoped to the authorized target."
            )
    try:
        configured = int(configured_tokens)
    except ValueError:
        configured = 16384
    retry_tokens = max(max_tokens, max(1024, min(configured, 32768)))
    return retry_messages, retry_tokens
