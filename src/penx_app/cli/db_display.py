#!/usr/bin/env python3
"""
PenX - db_display.py
CLI display helpers for session data.
"""


def print_history(rows):
    print("\n" + "─"*65)
    print(f"{'SL#':<6} {'TARGET':<28} {'DATE':<22} {'STATUS'}")
    print("─"*65)
    for row in rows:
        print(f"{row[0]:<6} {row[1]:<28} {str(row[2]):<22} {row[3]}")
    print()


def print_session(data: dict):
    h = data["history"]
    print(f"\n{'═'*60}")
    print(f"  SL# {h[0]} | Target: {h[1]} | {h[2]} | {h[3]}")
    print(f"{'═'*60}")

    print("\n[ VULNERABILITIES ]")
    # Keep rejected findings visible for audit, but label them explicitly.
    latest_status = {}
    for correction in sorted(data.get("corrections") or [], key=lambda x: x[0]):
        latest_status[correction[2]] = str(correction[3] or "").lower()
    CONF_COLORS = {
        "confirmed":      "\033[91m",   # red — high certainty
        "likely":         "\033[93m",   # yellow
        "possible":       "\033[90m",   # gray
        "recommendation": "\033[36m",   # cyan
    }
    RESET = "\033[0m"
    if data["vulns"]:
        for v in data["vulns"]:
            # v: id, sl_no, vuln_name, severity, confidence, port, service, description
            conf = v[4] or "possible"
            cc = CONF_COLORS.get(conf, "")
            sev_label = f"Severity: {v[3]}" if v[3] != "info" else "INFO"
            rejected = " [REJECTED: HALLUCINATION; NOT ACTIVE]" if latest_status.get(v[0]) == "hallucination" else ""
            print(f"  id={v[0]} | {v[2]}{rejected} | {sev_label} | {cc}{conf}{RESET} | Port: {v[5]} | Service: {v[6]}")
            print(f"           {v[7]}")
    else:
        print("  None recorded.")

    print("\n[ FIXES ]")
    if data["fixes"]:
        for f in data["fixes"]:
            print(f"  id={f[0]} | vuln_id={f[2]} | [{f[4]}] {f[3]}")
    else:
        print("  None recorded.")

    print("\n[ EXPLOITS ATTEMPTED ]")
    if data["exploits"]:
        for e in data["exploits"]:
            print(f"  id={e[0]} | {e[2]} | Tool: {e[3]} | Result: {e[5]}")
            print(f"           Payload: {e[4]}")
            print(f"           Notes:   {e[6]}")
    else:
        print("  None recorded.")

    print("\n[ CORRECTIONS / HALLUCINATIONS ]")
    if data.get("corrections"):
        STATUS_COLORS = {
            "hallucination": "\033[91m",
            "corrected":     "\033[93m",
            "verified":      "\033[92m",
            "downgraded":    "\033[33m",
            "reclassified":  "\033[36m",
        }
        for cr in data["corrections"]:
            sc = STATUS_COLORS.get(cr[3], "")
            print(f"  id={cr[0]} | vuln_id={cr[2]} | {sc}{cr[3].upper()}{RESET} | {cr[7]}")
            print(f"           Original : {cr[4]}")
            if cr[5]:
                print(f"           Corrected: {cr[5]}")
            print(f"           Reason   : {cr[6]}")
    else:
        print("  None recorded.")

    print("\n[ EVALUATIONS ]")
    if data.get("evaluations"):
        VERDICT_COLORS = {
            "valid":         "\033[92m",
            "hallucination": "\033[91m",
            "corrected":     "\033[93m",
            "downgraded":    "\033[33m",
            "reclassified":  "\033[36m",
        }
        for ev in data["evaluations"]:
            vc = VERDICT_COLORS.get(ev[5], "")
            checks = []
            if ev[7]:  checks.append("sev")
            if ev[8]:  checks.append("cve")
            if ev[9]:  checks.append("sw")
            if ev[10]: checks.append("fix")
            check_str = ",".join(checks) if checks else "none"
            print(f"  id={ev[0]} | vuln_id={ev[2]} | {vc}{ev[5].upper()}{RESET} [{ev[6]}] | by: {ev[3]}")
            print(f"           Correct: {check_str} | {ev[12]}")
            if ev[11]:
                print(f"           Notes: {ev[11][:120]}")
    else:
        print("  None recorded.")

    print("\n[ SUMMARY ]")
    if data["summary"]:
        s = data["summary"]
        print(f"  Risk Level : {s[4]}")
        print(f"  Generated  : {s[6]}")
        print(f"\n  AI Analysis:\n  {s[3][:500]}{'...' if len(str(s[3])) > 500 else ''}")
    else:
        print("  None recorded.")
    print()
