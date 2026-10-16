#!/usr/bin/env python3
"""
PenX - llm.py
Local LLM interface (LM Studio, Ollama, llama.cpp; OpenAI-compatible API).
Builds prompts, handles AI responses, runs tool dispatch loop.
"""

import re
import requests
import json
import os
from typing import TYPE_CHECKING, Callable
from penx_app.runtime_options import live_output
from datetime import datetime
from penx_app.scanners.tools import run_tool_by_command, run_nmap, run_curl_headers
from penx_app.analysis.ai_tool_protocol import parse_directives, dispatch_directives
from penx_app.intelligence.search import handle_search_dispatch
from penx_app.config import LLM_URL, LLM_MODELS_URL, LLM_BASE_URL, MODEL_NAME, MAX_TOKENS, TOP_K, MAX_TOOL_LOOPS, LLM_TIMEOUT, LLM_API_KEY, STRUCTURED_MODE, VERIFY_SOURCES, NVD_API_KEY, CVE_DISCOVERY, CVE_MAX_SERVICES, CVE_MAX_PACKAGES, CVE_MAX_RESULTS, GITHUB_ADVISORY_TOKEN, CVE_PRIORITY, CVE_DISTRO_HINT, CVE_MAX_VERIFY, PACKAGE_INVENTORY, DEBIAN_TRACKER_JSON
from penx_app.analysis.structured_output import request_structured_report
from penx_app.intelligence.source_verification import verify_findings
from penx_app.analysis.assessment_quality import review_evidence, reviewer_report, apply_review
from penx_app.intelligence.cve_engine import discover, format_report
from penx_app.analysis.scan_input_budget import bound_scan_text
from penx_app.analysis.structured_scan_evidence import model_evidence
from penx_app.intelligence.wordpress_advisories import research_plugins, format_plugin_report
from penx_app.intelligence.exploitdb_references import lookup as exploitdb_lookup, format_report as exploitdb_report
from penx_app.intelligence.source_verification import CVE_PATTERN
from penx_app.analysis.llm_client import complete_chat, fetch_models, ModelConfigurationError, EmptyModelResponse, explain_http_error
from penx_app.analysis.model_retry import prepare_empty_retry
from penx_app.analysis.prompts import SYSTEM_PROMPT, REVIEW_PROMPT

if TYPE_CHECKING:
    from penx_app.settings import Settings

# ─────────────────────────────────────────────
# CORRECTION FEEDBACK LOOP
# ─────────────────────────────────────────────

def load_correction_rules() -> str:
    """
    Load learned rules for injection into the system prompt.

    Priority: learned_rules table (distilled by external LLM) > raw corrections.
    If distilled rules exist, use those — they're compact and fit in context.
    If no distilled rules exist, fall back to a lightweight summary of raw corrections.
    """
    try:
        from penx_app.storage.correction_repository import load_correction_rules as read
        return read()
    except Exception:
        # Correction hints are optional; the assessment remains usable when
        # the reviewer database is unavailable.
        return ""


def _read_correction_rules(conn) -> str:
    from penx_app.storage.correction_repository import _read_correction_rules as read
    return read(conn)


def build_system_prompt() -> str:
    """
    Build the full system prompt by combining the base prompt
    with any learned corrections from the database.
    """
    correction_rules = load_correction_rules()
    if correction_rules:
        return SYSTEM_PROMPT + "\n" + correction_rules
    return SYSTEM_PROMPT


# ─────────────────────────────────────────────
# SELF-REVIEW PASS
# ─────────────────────────────────────────────

def self_review(raw_scan: str, ai_analysis: str, correction_rules: str,
                ask: Callable[[list], str] | None = None) -> dict:
    """
    Run a self-review pass on the AI analysis to catch errors
    before they get saved to the database.
    Returns dict with reviews and adjusted risk level.
    """
    if ask is None:
        ask = ask_llm
    messages = [
        {"role": "system", "content": REVIEW_PROMPT},
        {"role": "user", "content": f"""RAW SCAN DATA:
{review_evidence(raw_scan)}

AI ANALYSIS TO REVIEW:
{ai_analysis[:22000]}

{correction_rules if correction_rules else "No prior correction history available."}

Review each FINAL vulnerability and recommendation by its exact REVIEW THIS EXACT NAME label. Be thorough."""}
    ]

    print("\n[*] Running self-review pass...")
    response = ask(messages)

    if response.startswith("[!]"):
        print(f"  [!] Self-review failed: {response}")
        return {"review": "", "adjusted_risk": "", "flags": []}

    print(f"\n{'─'*60}")
    print("[PenX - Self-Review]")
    print(f"{'─'*60}")
    print(response)

    # Parse review verdicts with evidence and issue details
    flags = []

    # Split response into blocks per REVIEW: line
    blocks = re.split(r'(?=REVIEW:)', response, flags=re.IGNORECASE)
    for block in blocks:
        block = block.strip()
        match = re.match(r'REVIEW:\s*(.+?)\s*\|\s*VERDICT:\s*(\w+)', block, re.IGNORECASE)
        if not match:
            continue

        vuln_name = match.group(1).strip()
        verdict = match.group(2).strip().lower()

        # Extract EVIDENCE and ISSUE fields from the block
        evidence_match = re.search(r'EVIDENCE:\s*(.+?)(?=\n[A-Z]+:|$)', block, re.IGNORECASE | re.DOTALL)
        issue_match = re.search(r'ISSUE:\s*(.+?)(?=\n[A-Z]+:|$)', block, re.IGNORECASE | re.DOTALL)
        corrected_match = re.search(r'CORRECTED:\s*(.+?)(?=\n[A-Z]+:|$)', block, re.IGNORECASE | re.DOTALL)

        evidence = evidence_match.group(1).strip() if evidence_match else ""
        issue = issue_match.group(1).strip() if issue_match else ""
        corrected = corrected_match.group(1).strip() if corrected_match else ""

        flag = {
            "vuln_name": vuln_name,
            "verdict": verdict,
            "evidence": evidence,
            "issue": issue,
            "corrected": corrected
        }
        flags.append(flag)

    adjusted_risk = ""
    risk_match = re.search(
        r'ADJUSTED_RISK_LEVEL:\s*(CRITICAL|HIGH|MEDIUM|LOW)',
        response, re.IGNORECASE
    )
    if risk_match:
        adjusted_risk = risk_match.group(1).upper()

    flagged = [f for f in flags if f["verdict"] != "valid"]
    if flagged:
        print(f"\n[!] Self-review flagged {len(flagged)} finding(s):")
        for f in flagged:
            print(f"    - {f['vuln_name']}: {f['verdict']}")
            if f["issue"]:
                print(f"      Issue: {f['issue'][:100]}")
    else:
        print("\n[+] Self-review: all findings appear valid.")

    if adjusted_risk:
        print(f"[*] Adjusted risk level: {adjusted_risk}")

    return {
        "review": response,
        "adjusted_risk": adjusted_risk,
        "flags": flags
    }


# ─────────────────────────────────────────────
# SHARED LOCAL LLM API (LM Studio / Ollama / llama.cpp)
# ─────────────────────────────────────────────

def ask_llm(messages: list, settings: "Settings | None" = None, *,
            complete: Callable | None = None, emit: Callable | None = None,
            stream_emit: Callable | None = None) -> str:
    """Analyze with a bounded retry for reasoning-only or otherwise empty output.

    On an empty SSE response, retry ONCE non-streaming. This also works around
    servers that advertise SSE but only populate the non-streaming message.
    Never mistake a private reasoning trace for a usable final assessment.

    ``settings`` is an explicit configuration snapshot (``penx_app.settings.
    Settings``). When omitted, the module-level configuration values are
    used, preserving the legacy behavior for direct callers.
    """
    if settings is None:
        url, models_url, base_url = LLM_URL, LLM_MODELS_URL, LLM_BASE_URL
        model_name, api_key = MODEL_NAME, LLM_API_KEY
        max_tokens, timeout, top_k = MAX_TOKENS, LLM_TIMEOUT, TOP_K
    else:
        url, models_url, base_url = settings.LLM_URL, settings.LLM_MODELS_URL, settings.LLM_BASE_URL
        model_name, api_key = settings.MODEL_NAME, settings.LLM_API_KEY
        max_tokens, timeout, top_k = settings.MAX_TOKENS, settings.LLM_TIMEOUT, settings.TOP_K
    transport = complete_chat if complete is None else complete
    # The current terminal is the default adapter, not a use-case requirement.
    # GUI/headless callers may supply progress and delta ports per request.
    output = print if emit is None else emit

    def write_chunk(chunk: str) -> None:
        if stream_emit is None:
            print(chunk, end="", flush=True)
        else:
            stream_emit(chunk)

    try:
        live = live_output()
        if live:
            if emit is None:
                print("\n[AI STREAM] ", end="", flush=True)
            else:
                emit("\n[AI STREAM] ")
        try:
            model_id, response = transport(
                messages, url=url, models_url=models_url,
                model_name=model_name, api_key=api_key,
                max_tokens=max_tokens, timeout=timeout,
                top_k=top_k,
                **({"stream_callback": write_chunk}
                   if live else {}),
            )
        except EmptyModelResponse as first_error:
            retry_allowed = os.getenv("PENX_LLM_RETRY_EMPTY", "on").lower() not in (
                "off", "false", "0", "no"
            )
            if not retry_allowed:
                raise
            output(f"\n[!] {first_error}")
            output("[*] Retrying the LLM response once without streaming or thinking output...")
            retry_messages, retry_tokens = prepare_empty_retry(
                messages, max_tokens, os.getenv("PENX_LLM_RETRY_TOKENS", "16384"),
            )
            model_id, response = transport(
                retry_messages, url=url, models_url=models_url,
                model_name=model_name, api_key=api_key,
                max_tokens=retry_tokens, timeout=timeout,
                top_k=top_k, temperature=0.2,
                # Non-streaming deliberately avoids a second broken SSE path.
            )
            if live and response:
                output("\n[AI RETRY RESPONSE]\n" + response)
        output(f"\n[*] Response received from {model_id}.")
        return response
    except EmptyModelResponse as exc:
        return (
            f"[!] Local model did not produce a final answer after retry: {exc} "
            "Try PENX_MAX_TOKENS=16384 or 32768 and configure Qwen with "
            "thinking disabled, or check the local server's chat template."
        )
    except ModelConfigurationError as exc:
        return f"[!] LLM configuration: {exc}"
    except requests.exceptions.ConnectionError:
        return f"[!] Cannot connect to the local LLM at {base_url}. Is the server running?"
    except requests.exceptions.Timeout:
        return "[!] LLM request timed out. Check whether the model is still loading."
    except requests.exceptions.HTTPError as exc:
        return f"[!] LLM HTTP error: {explain_http_error(exc)}"
    except Exception as exc:
        return f"[!] Unexpected LLM error: {exc}"


# ─────────────────────────────────────────────
# TOOL DISPATCH
# ─────────────────────────────────────────────

def extract_tool_calls(response: str) -> list:
    """Compatibility facade for model directive parsing."""
    return parse_directives(response)



def summarize_tool_output(raw_output: str,
                          complete: Callable[[list], tuple] | None = None) -> str:
    """Compress long tool output with the same configured local backend.

    ``complete`` is a bound ``(messages) -> (model_id, text)`` transport.
    When omitted, the module-level configuration values are used.
    """
    if len(raw_output) < 500:
        return raw_output
    if complete is None:
        def complete(messages: list) -> tuple:
            return complete_chat(
                messages, url=LLM_URL, models_url=LLM_MODELS_URL,
                model_name=MODEL_NAME, api_key=LLM_API_KEY,
                max_tokens=512, timeout=min(LLM_TIMEOUT, 120), temperature=0.2,
                top_k=TOP_K,
            )
    try:
        _, summary = complete([
            {"role": "system", "content": "You are a security data compressor. Extract only security-relevant facts. Return maximum 15 bullet points. Plain text only. No markdown."},
            {"role": "user", "content": f"Compress this tool output:\n{raw_output[:6000]}"},
        ])
        return summary or raw_output
    except Exception:
        # Compression is optional; never discard the raw evidence on failure.
        return raw_output


def run_tool_calls(calls: list, authorized_target: str | None = None, raw_collector: list | None = None,
                  summarizer: Callable[[str], str] | None = None,
                  scanner_runner: Callable | None = None,
                  search_runner: Callable | None = None) -> str:
    """Dispatch fixed authorized adapters through explicit, mockable client ports.

    Legacy callers keep the same default scanner/search handlers. Supplying
    injected handlers does not relax dispatch_directives target authorization.
    """
    if summarizer is None:
        summarizer = summarize_tool_output
    if scanner_runner is None:
        scanner_runner = run_tool_by_command
    if search_runner is None:
        search_runner = handle_search_dispatch
    return dispatch_directives(
        calls, authorized_target=authorized_target, raw_collector=raw_collector,
        scanner_runner=scanner_runner, search_runner=search_runner,
        summarizer=summarizer,
    )


# ─────────────────────────────────────────────
# PARSER — imported from parsers.py
# ─────────────────────────────────────────────
from penx_app.analysis.parsers import parse_vulnerabilities, parse_recommendations, parse_exploits, parse_risk_level, parse_summary


# ─────────────────────────────────────────────
# MAIN ANALYSIS FUNCTION
# ─────────────────────────────────────────────

def analyse_target(target: str, raw_scan: str, *, passive_only: bool = False) -> dict:
    """Legacy facade; the pipeline receives one explicit dependency snapshot."""
    from penx_app.analysis.analysis_pipeline import analyse_target as analyse, AnalysisPorts
    from penx_app.settings import Settings
    from types import MappingProxyType
    from penx_app.config import SCAN_INPUT_MAX_CHARS
    from penx_app.app_paths import APP_ROOT
    settings = Settings(MappingProxyType({
        "CVE_DISCOVERY": CVE_DISCOVERY,
        "CVE_DISTRO_HINT": CVE_DISTRO_HINT,
        "CVE_MAX_PACKAGES": CVE_MAX_PACKAGES,
        "CVE_MAX_RESULTS": CVE_MAX_RESULTS,
        "CVE_MAX_SERVICES": CVE_MAX_SERVICES,
        "CVE_MAX_VERIFY": CVE_MAX_VERIFY,
        "CVE_PRIORITY": CVE_PRIORITY,
        "DEBIAN_TRACKER_JSON": DEBIAN_TRACKER_JSON,
        "GITHUB_ADVISORY_TOKEN": GITHUB_ADVISORY_TOKEN,
        "LLM_API_KEY": LLM_API_KEY,
        "LLM_BASE_URL": LLM_BASE_URL,
        "LLM_MODELS_URL": LLM_MODELS_URL,
        "LLM_TIMEOUT": LLM_TIMEOUT,
        "LLM_URL": LLM_URL,
        "MAX_TOKENS": MAX_TOKENS,
        "MAX_TOOL_LOOPS": MAX_TOOL_LOOPS,
        "MODEL_NAME": MODEL_NAME,
        "NVD_API_KEY": NVD_API_KEY,
        "PACKAGE_INVENTORY": PACKAGE_INVENTORY,
        "SCAN_INPUT_MAX_CHARS": SCAN_INPUT_MAX_CHARS,
        "STRUCTURED_MODE": STRUCTURED_MODE,
        "TOP_K": TOP_K,
        "VERIFY_SOURCES": VERIFY_SOURCES,
    }))

    # Bind every model transport to this single configuration snapshot so an
    # in-flight analysis never mixes two configuration generations.
    def bound_ask(messages: list) -> str:
        return ask_llm(messages, settings=settings)

    def bound_self_review(raw: str, items: str, rules: str) -> dict:
        return self_review(raw, items, rules, ask=bound_ask)

    def bound_summarizer(text: str) -> str:
        return summarize_tool_output(text, complete=bound_complete)

    def bound_complete(messages: list) -> tuple:
        return complete_chat(
            messages, url=settings.LLM_URL, models_url=settings.LLM_MODELS_URL,
            model_name=settings.MODEL_NAME, api_key=settings.LLM_API_KEY,
            max_tokens=512, timeout=min(settings.LLM_TIMEOUT, 120),
            temperature=0.2, top_k=settings.TOP_K,
        )

    ports = AnalysisPorts(
        format_report=format_report,
        discover=discover,
        research_plugins=research_plugins,
        build_system_prompt=build_system_prompt,
        load_correction_rules=load_correction_rules,
        ask_llm=bound_ask,
        extract_tool_calls=extract_tool_calls,
        run_tool_calls=lambda calls, authorized_target=None, raw_collector=None:
            run_tool_calls(calls, authorized_target=authorized_target,
                           raw_collector=raw_collector, summarizer=bound_summarizer),
        request_structured_report=request_structured_report,
        self_review=bound_self_review,
        verify_findings=verify_findings,
        exploitdb_lookup=exploitdb_lookup,
        live_output=live_output,
        app_root=APP_ROOT, emit=print)
    return analyse(target, raw_scan, settings=settings, ports=ports, passive_only=passive_only)
# ─────────────────────────────────────────────
# QUICK TEST
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("[ llm.py test — direct AI query ]\n")

    # Check the selected OpenAI-compatible local model server.
    try:
        models = fetch_models(LLM_MODELS_URL, api_key=LLM_API_KEY, timeout=5)
        if not models:
            print("[!] Local LLM server is responding, but no models were listed.")
            exit(1)
        print(f"[+] Local LLM server models: {', '.join(models)}")
    except Exception:
        print(f"[!] Local LLM server unavailable at {LLM_BASE_URL}. Is it running?")
        exit(1)

    target = input("Test target: ").strip()
    test_scan = f"Test recon for {target} — nmap and whois data would appear here."
    result = analyse_target(target, test_scan)

    print(f"\nRisk Level : {result['risk_level']}")
    print(f"Summary    : {result['summary']}")
    print(f"Vulns found: {len(result['vulnerabilities'])}")
    print(f"Exploits   : {len(result['exploits'])}")
