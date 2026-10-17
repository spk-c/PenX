"""Parse model-requested directives and assemble bounded adapter results.

Dispatch remains scoped to externally supplied fixed scanner/search adapters.
This file never evaluates directives as Python or executes arbitrary commands.
"""
from __future__ import annotations
import re

from penx_app.domain.scan_models import ScannerOutput

# A single model response must not trigger unbounded search/scan calls.
MAX_DIRECTIVES_PER_ROUND = 12
MAX_TOOL_INPUT_CHARS = 24_000
MAX_TOOL_RESULT_CHARS = 12_000
MAX_TOOL_ROUND_CHARS = 96_000
MAX_TOOL_RAW_EVIDENCE_CHARS = 2_000_000


def parse_directives(response: str) -> list:
    """Extract inline TOOL and SEARCH directives in their original order.

    Allow a single bracketed token inside a directive (for IPv6 hosts such as
    [::1]), but do not consume adjacent tags, other lines, or trailing prose.
    Scanner commands remain checked by run_tool_by_command before execution.
    """
    pattern = r'\[(TOOL|SEARCH):[ \t]*((?:[^\[\]\r\n]|\[[^\[\]\r\n]*\]){1,2048})\]'
    calls = []
    for match in re.finditer(pattern, response, re.IGNORECASE):
        command = match.group(2).strip()
        if command:
            calls.append((match.group(1).upper(), command))
            if len(calls) >= MAX_DIRECTIVES_PER_ROUND:
                break
    return calls


def dispatch_directives(calls: list, authorized_target: str | None = None, raw_collector: list | None = None,
                        *, scanner_runner, search_runner, summarizer) -> str:
    """
    Execute all tool/search calls and return combined results string.
    """
    if not calls:
        return ""

    limited = calls[:MAX_DIRECTIVES_PER_ROUND]
    parts: list[str] = []
    used = 0
    skipped_for_budget = 0
    for index, (call_type, call_content) in enumerate(limited):
        if used >= MAX_TOOL_ROUND_CHARS:
            skipped_for_budget = len(limited) - index
            break
        # Parsed directives already limit commands to 2048 characters. The
        # dispatcher is public, so do not let direct callers bypass that rule
        # or echo unlimited tool instructions into the model's context.
        if (not isinstance(call_type, str) or not isinstance(call_content, str)
                or len(call_content) > 2048):
            call_type, call_content = "INVALID", "[invalid tool directive]"
        print(f"\n  [DISPATCH] {call_type}: {call_content[:256]}")

        if call_type == "TOOL":
            output = scanner_runner(call_content, authorized_target=authorized_target)
        elif call_type == "SEARCH":
            output = search_runner(call_content)
        else:
            output = f"[!] Unknown call type: {call_type}"

        # Only completed, evidence-bearing typed scanner responses or
        # nonempty legacy text without diagnostic prefixes can be retained.
        # Never treat a failed/partial ScannerOutput or arbitrary object repr
        # as scanner evidence merely because its text looks nonempty.
        typed = isinstance(output, ScannerOutput)
        trusted = (
            output.status == "COMPLETE" and output.evidence if typed
            else isinstance(output, str)
        )
        if output is None:
            output = "[!] Tool returned no output."
        elif not isinstance(output, str):
            output = "[!] Tool returned unsupported output type."
        diagnostic = not output.strip() or output.lstrip().startswith(
            ("[!]", "[EXIT CODE", "[ERROR]", "Traceback ")
        )
        if raw_collector is not None and call_type == "TOOL":
            if trusted and not diagnostic:
                # Raw evidence remains separate from model-facing summaries.
                raw_collector.append(
                    "\n[ADDITIONAL TOOL OUTPUT]\n"
                    + output[:MAX_TOOL_RAW_EVIDENCE_CHARS]
                )
        source = output.strip()
        clipped_input = source[:MAX_TOOL_INPUT_CHARS]
        compressed = summarizer(clipped_input)
        if not isinstance(compressed, str):
            compressed = "[!] Tool summarizer returned unsupported output type."
        # Optional compression can fail and return the full raw input. Never
        # let the raw fallback or an abnormal model summary grow unbounded.
        max_body = min(
            MAX_TOOL_RESULT_CHARS,
            max(0, MAX_TOOL_ROUND_CHARS - used
                - len(call_type) - len(call_content) - 80),
        )
        shortened = len(compressed) > max_body or len(source) > MAX_TOOL_INPUT_CHARS
        body = compressed[:max_body]
        if shortened:
            body += "\n[!] Tool result truncated for model context; stored scanner evidence is separate."
        block = (f"\n[{call_type} RESULT: {call_content}]\n"
                 + "─" * 40 + "\n" + body + "\n")
        remaining = MAX_TOOL_ROUND_CHARS - used
        if len(block) > remaining:
            block = block[:remaining]
        parts.append(block)
        used += len(block)

    skipped = max(0, len(calls) - MAX_DIRECTIVES_PER_ROUND) + skipped_for_budget
    if skipped:
        note = (
            f"\n[!] Skipped {skipped} "
            "model tool/search requests: per-round limit reached.\n"
        )
        remaining = MAX_TOOL_ROUND_CHARS - used
        if remaining:
            parts.append(note[:remaining])
    return "".join(parts)
