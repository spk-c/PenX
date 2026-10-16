"""Parse model-requested directives and assemble bounded adapter results.

Dispatch remains scoped to externally supplied fixed scanner/search adapters.
This file never evaluates directives as Python or executes arbitrary commands.
"""
from __future__ import annotations
import re

from penx_app.domain.scan_models import ScannerOutput

# A single model response must not trigger unbounded search/scan calls.
MAX_DIRECTIVES_PER_ROUND = 12


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
    results = ""
    for call_type, call_content in limited:
        print(f"\n  [DISPATCH] {call_type}: {call_content}")

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
                # Tool text used for later CVE discovery must be real evidence.
                raw_collector.append("\n[ADDITIONAL TOOL OUTPUT]\n" + output[:2_000_000])
        compressed = summarizer(output.strip())
        results += f"\n[{call_type} RESULT: {call_content}]\n"
        results += "─" * 40 + "\n"
        results += compressed + "\n"

    if len(calls) > MAX_DIRECTIVES_PER_ROUND:
        results += (
            f"\n[!] Skipped {len(calls) - MAX_DIRECTIVES_PER_ROUND} "
            "model tool/search requests: per-round limit reached.\n"
        )
    return results
