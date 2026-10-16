#!/usr/bin/env python3
"""PenX reporting entrypoints and interactive export menu.

Presentation is shared by HTML and PDF in report_design.py, and always
runs against the active-finding-filtered, saved session data.
"""
import os
from penx_app.app_paths import APP_ROOT
from html import escape as html_escape
from penx_app.reporting.report_view import ReportView

from penx_app.reporting.report_design import export_html as _branded_html, export_pdf as _branded_pdf


def safe_text(value):
    """Escape untrusted report values for HTML and terminal use."""
    return html_escape(str(value), quote=True)


def fetch_session(sl_no: int) -> dict:
    from penx_app.storage.db import get_session
    return add_saved_comparison(get_session(sl_no))


def add_saved_comparison(data: dict) -> dict:
    """Attach a previous saved scan comparison without probing a live target."""
    if not data.get("history") or not data.get("summary"):
        return data
    from penx_app.application.scan_trends import matching_history, compare_sessions, report_text
    from penx_app.storage.db import get_session
    current = data["history"]
    previous = [row for row in matching_history(current[1]) if int(row[0]) < int(current[0])]
    if not previous:
        return data
    older = get_session(max(previous, key=lambda row: int(row[0]))[0])
    diff = compare_sessions(older, data)
    return {**data, "comparison": report_text(diff)}


def fetch_all_history():
    from penx_app.storage.db import get_all_history
    return get_all_history()



def _active_report_data(data: dict) -> dict:
    """Compatibility boundary; use the common saved-session report projection."""
    return ReportView.from_session(data).as_legacy()


def export_pdf(data: dict, output_dir: str, *, mode: str = "technical") -> str:
    """Export reviewed findings with the branded, paginated PDF layout."""
    return _branded_pdf(_active_report_data(data), output_dir, mode=mode)


def export_html(data: dict, output_dir: str, *, mode: str = "technical") -> str:
    """Export reviewed findings with the responsive dark PenX layout."""
    return _branded_html(_active_report_data(data), output_dir, mode=mode)


def export_menu(data: dict):
    if not data["history"]:
        print("[!] No session data to export.")
        return

    h   = data["history"]
    sl  = h[0]
    tgt = h[1]

    print(f"\n\033[33m{'─'*20} EXPORT SL#{sl} — {safe_text(tgt)} {'─'*20}\033[0m")
    print("  [1] PDF report")
    print("  [2] HTML report")
    print("  [3] Both")
    print("  [4] Back")
    print("  [5] Executive PDF + HTML")
    print("  [6] JSON (reviewed findings, no raw scanner output)")
    print("  [7] SARIF 2.1 (reviewed findings)")
    print("  [8] Redacted JSON + SARIF (target / IPv4 masked)")
    print("  [0] Back to previous menu (also: b / back)")
    print(f"\033[90m{'─'*60}\033[0m")

    from penx_app.cli.cli_navigation import is_back, navigation_input
    choice = navigation_input("\033[36mExport format (Esc=Back): \033[0m").strip()
    if choice == "4" or is_back(choice):
        return
    output_dir = str(APP_ROOT / "reports")
    os.makedirs(output_dir, exist_ok=True)

    if choice == "1":
        p = export_pdf(data, output_dir)
        print(f"\033[92m[+] PDF saved: {p}\033[0m")
    elif choice == "2":
        p = export_html(data, output_dir)
        print(f"\033[92m[+] HTML saved: {p}\033[0m")
    elif choice == "3":
        p1 = export_pdf(data, output_dir)
        p2 = export_html(data, output_dir)
        print(f"\033[92m[+] PDF  : {p1}\033[0m")
        print(f"\033[92m[+] HTML : {p2}\033[0m")
    elif choice == "5":
        p1 = export_pdf(data, output_dir, mode="executive")
        p2 = export_html(data, output_dir, mode="executive")
        print(f"[+] Executive PDF: {p1}\n[+] Executive HTML: {p2}")
    elif choice in ("6", "7", "8"):
        from penx_app.reporting.machine_reports import write_machine_report
        formats = ("json", "sarif") if choice == "8" else ({"6": "json", "7": "sarif"}[choice],)
        for fmt in formats:
            output = write_machine_report(data, output_dir, fmt=fmt, redact=(choice == "8"))
            print(f"[+] {fmt.upper()} saved: {output}")
    else:
        print("\033[93m[!] Invalid choice.\033[0m")


if __name__ == "__main__":
    print("\n\033[91m    PenX — Standalone Report Exporter\033[0m")
    print("\033[90m    ─────────────────────────────────────\033[0m\n")

    rows = fetch_all_history()
    if not rows:
        print("[!] No sessions found in database.")
        exit()

    print(f"{'SL#':<6} {'TARGET':<28} {'DATE':<22} {'STATUS'}")
    print("─" * 65)
    for row in rows:
        print(f"{row[0]:<6} {row[1]:<28} {str(row[2]):<22} {row[3]}")
    print()

    sl_input = input("\033[36mEnter SL# to export: \033[0m").strip()
    if not sl_input.isdigit():
        print("[!] Invalid SL#.")
        exit()

    data = fetch_session(int(sl_input))
    if not data["history"]:
        print(f"[!] SL# {sl_input} not found.")
        exit()

    export_menu(data)
