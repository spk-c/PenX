"""Terminal workflows for scan trends and reviewable risk prioritization."""
from __future__ import annotations

from pathlib import Path

from penx_app.app_paths import APP_ROOT
from penx_app.cli.cli_navigation import is_back, show_back, navigation_input
from penx_app.storage.db import get_all_history, get_session
from penx_app.application.scan_trends import matching_history, compare_ids, report_text, save_diff, history_trend, export_diff_reports
from penx_app.application.risk_assessment import assessment_for_session, save_override, risk_report_json


def compare_menu() -> None:
    rows = get_all_history()
    candidates = sorted({x[1] for x in rows
                         if sum(1 for r in rows if r[1] == x[1]) >= 2})
    print("\n[SCAN DIFF AND TRENDS]")
    if not candidates:
        print("At least two saved scans of the same target are required.")
        return
    for target in candidates:
        print(f"  {target}")
    show_back()
    target = navigation_input("Target to compare (Esc=Back): ").strip()
    if is_back(target):
        return
    matches = matching_history(target)
    if len(matches) < 2:
        print("[!] Two matching sessions are required.")
        return
    for row in matches:
        print(f"  SL#{row[0]} | {row[2]} | {row[3]}")
    show_back("Back to main menu; Enter uses the proposed session")
    older = navigation_input(f"Older session [default {matches[-2][0]}] (Esc=Back): ").strip()
    if is_back(older):
        return
    newer = navigation_input(f"Newer session [default {matches[-1][0]}] (Esc=Back): ").strip()
    if is_back(newer):
        return
    try:
        older_id = int(older) if older else matches[-2][0]
        newer_id = int(newer) if newer else matches[-1][0]
        if older_id == newer_id:
            raise ValueError("Choose two different sessions.")
        diff = compare_ids(older_id, newer_id)
        print("\n" + report_text(diff))
        print("\n[TREND]")
        for row in history_trend(target):
            print(f"  SL#{row['session']} {row['date']} | "
                  f"{row['risk']:<9} | findings={row['findings']}")
        paths = export_diff_reports(diff, APP_ROOT / "reports")
        print("[+] Comparison reports: " + ", ".join(str(v) for v in paths.values()))
        if input("Summarize diff with your local AI model? [y/N]: ").strip().lower() == "y":
            print("\n" + ai_diff_summary(diff))
    except (ValueError, OSError) as exc:
        print(f"[!] Cannot compare sessions: {exc}")


def ai_diff_summary(diff: dict) -> str:
    """Optional narration, never a substitute for the deterministic diff."""
    from penx_app.config import LLM_URL, LLM_MODELS_URL, MODEL_NAME, LLM_API_KEY
    from penx_app.analysis.llm_client import complete_chat
    deterministic = report_text(diff)
    try:
        _, summary = complete_chat(
            [
                {"role": "system", "content": (
                    "Summarize only the provided scan diff. Do not invent versions, "
                    "hosts, exploits, or remediation status. Missing findings are "
                    "not proof of remediation. Avoid commands and tool tags."
                )},
                {"role": "user", "content": deterministic[:12000]},
            ],
            url=LLM_URL, models_url=LLM_MODELS_URL, model_name=MODEL_NAME,
            api_key=LLM_API_KEY, max_tokens=500, timeout=120, temperature=0.1
        )
        return summary or "[!] Model returned an empty summary."
    except Exception as exc:
        return f"[!] Local AI summary unavailable: {type(exc).__name__}: {exc}"


def automatic_regression_check(session_id: int) -> None:
    """After an authorized scan, alert about observed changes from prior scan."""
    current = get_session(session_id)
    if not current.get("history"):
        return
    target = current["history"][1]
    previous = [r for r in matching_history(target) if r[0] < session_id]
    if not previous:
        return
    diff = compare_ids(previous[-1][0], session_id)
    print("\n[REGRESSION CHECK: previous scan vs current]")
    print(report_text(diff))
    if diff["new_findings"] or diff["new_ports"] or diff["severity_changes"]:
        print("[!] Changed observations deserve review; verify scan coverage.")


def risk_menu() -> None:
    print("\n[RISK PRIORITIZATION / MITRE ATT&CK]")
    rows = get_all_history()
    if not rows:
        print("No saved scans.")
        return
    for row in rows[:20]:
        print(f"  SL#{row[0]} | {row[1]} | {row[2]}")
    show_back()
    response = navigation_input("Session ID (Esc=Back): ").strip()
    if is_back(response):
        return
    if not response.isdigit():
        print("[!] Invalid session ID.")
        return
    sl = int(response)
    try:
        findings = assessment_for_session(sl)
        if not findings:
            print("No findings recorded.")
            return
        for f in findings:
            tactics = ", ".join(x["id"] + " (" + x["status"] + ")"
                                for x in f["techniques"]) or "No justified mapping"
            score_label = (f"{f['score']:3}/100" if f['score'] is not None
                           else "N/A (hardening task)")
            print(f"\n  #{f['finding_id']} | {score_label} "
                  f"({f['status']}) | {f['severity']} | {f['name']}")
            print(f"     Priority: {f['priority']} | ATT&CK: {tactics}")
        path = risk_report_json(sl, APP_ROOT / "reports")
        print(f"\n[+] Assessment JSON: {path}")
        edit = navigation_input("Override a finding ID (Enter/Esc=Back): ").strip()
        if not edit or is_back(edit):
            return
        if not edit.isdigit() or int(edit) not in {f["finding_id"] for f in findings}:
            raise ValueError("Unknown finding ID.")
        selected = next(f for f in findings if f["finding_id"] == int(edit))
        score_str = (input("Risk score 0-100 (blank = calculated): ").strip()
                     if selected["score"] is not None else "")
        technique_str = (input("ATT&CK technique IDs, comma-separated (blank = suggested): ").strip()
                         if selected["score"] is not None else "")
        priority = input("Priority quick win/planned (blank = calculated): ").strip()
        score = int(score_str) if score_str else None
        techniques = [x.strip().upper() for x in technique_str.split(",")
                      if x.strip()] if technique_str else None
        save_override(sl, int(edit), score=score, techniques=techniques,
                      priority=priority or None)
        print("[+] Manual review saved. Reopen the assessment to refresh.")
    except (ValueError, OSError) as exc:
        print(f"[!] Assessment failed: {exc}")
