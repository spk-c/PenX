"""Session-scoped edit/correction/delete dialog. No direct SQL imports."""
from __future__ import annotations

def edit_delete_menu(sl_no: int, *, divider, show_back, prompt, is_back, warn, error, success, confirm, _apply_edit, _apply_delete, info, format_vulnerability_picker, RISK_LEVELS, get_vulnerabilities, get_fixes, get_exploits, get_corrections, edit_vulnerability, edit_fix, edit_exploit, edit_summary_risk, delete_vulnerability, delete_fix, delete_exploit, save_correction, edit_correction, delete_correction, delete_full_session):
    while True:
        divider(f"EDIT / DELETE — SL# {sl_no}")
        print("  [1]  Edit a vulnerability")
        print("  [2]  Edit a fix")
        print("  [3]  Edit an exploit")
        print("  [4]  Edit risk level")
        print("  [5]  Delete a vulnerability")
        print("  [6]  Delete a fix")
        print("  [7]  Delete an exploit")
        print("  [8]  Add a correction / hallucination record")
        print("  [9]  Edit a correction")
        print("  [10] Delete a correction")
        print("  [11] Delete FULL session (all tables)")
        print("  [12] Back")
        show_back("Back to previous menu")
        divider()

        choice = prompt("Choice (Esc=Back): ", navigation=True)
        if is_back(choice):
            break

        # ── EDIT VULNERABILITY ─────────────────
        if choice == "1":
            vulns = get_vulnerabilities(sl_no)
            if not vulns:
                warn("No vulnerabilities recorded for this session.")
                continue

            print("\n[ VULNERABILITIES ]")
            for v in vulns:
                print(format_vulnerability_picker(v))

            vid = prompt("Enter vulnerability id to edit: ")
            if not vid.isdecimal():
                error("Invalid id.")
                continue

            print("  Fields: vuln_name / severity / confidence / port / service / description")
            field = prompt("Field to edit: ").strip()
            if field not in {"vuln_name", "severity", "confidence", "port", "service", "description"}:
                error("Invalid vulnerability field.")
                continue
            value = prompt(f"New value for '{field}': ")
            _apply_edit(
                "Vulnerability",
                lambda _id=int(vid), _field=field, _value=value: edit_vulnerability(
                    _id, _field, _value, sl_no=sl_no))

        # ── EDIT FIX ──────────────────────────
        elif choice == "2":
            fixes = get_fixes(sl_no)
            if not fixes:
                warn("No fixes recorded for this session.")
                continue

            print("\n[ FIXES ]")
            for f in fixes:
                print(f"  id={f[0]} | vuln_id={f[2]} | {f[3][:80]}")

            fid = prompt("Enter fix id to edit: ")
            if not fid.isdecimal():
                error("Invalid id.")
                continue

            new_text = prompt("New fix text: ")
            _apply_edit("Fix",
                        lambda _id=int(fid), _text=new_text: edit_fix(
                            _id, _text, sl_no=sl_no))

        # ── EDIT EXPLOIT ──────────────────────
        elif choice == "3":
            exploits = get_exploits(sl_no)
            if not exploits:
                warn("No exploits recorded for this session.")
                continue

            print("\n[ EXPLOITS ]")
            for e in exploits:
                print(f"  id={e[0]} | {e[2]} | tool: {e[3]} | result: {e[5]}")

            eid = prompt("Enter exploit id to edit: ")
            if not eid.isdecimal():
                error("Invalid id.")
                continue

            print("  Fields: exploit_name / tool_used / payload / result / notes")
            field = prompt("Field to edit: ").strip()
            if field not in {"exploit_name", "tool_used", "payload", "result", "notes"}:
                error("Invalid exploit field.")
                continue
            value = prompt(f"New value for '{field}': ")
            _apply_edit(
                "Exploit",
                lambda _id=int(eid), _field=field, _value=value: edit_exploit(
                    _id, _field, _value, sl_no=sl_no))

        # ── EDIT RISK LEVEL ───────────────────
        elif choice == "4":
            print("  Options: CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN")
            risk = prompt("New risk level: ").upper()
            if risk not in RISK_LEVELS:
                error("Invalid risk level.")
                continue
            _apply_edit("Risk level",
                        lambda _risk=risk: edit_summary_risk(sl_no, _risk))

        # ── DELETE VULNERABILITY ──────────────
        elif choice == "5":
            vulns = get_vulnerabilities(sl_no)
            if not vulns:
                warn("No vulnerabilities to delete.")
                continue

            print("\n[ VULNERABILITIES ]")
            for v in vulns:
                print(format_vulnerability_picker(v))

            vid = prompt("Enter vulnerability id to delete: ")
            if not vid.isdecimal():
                error("Invalid id.")
                continue

            if confirm(f"Delete vulnerability id={vid} and linked fixes, corrections and evaluations?"):
                _apply_delete(
                    "Vulnerability",
                    lambda _id=int(vid): delete_vulnerability(
                        _id, sl_no=sl_no))

        # ── DELETE FIX ────────────────────────
        elif choice == "6":
            fixes = get_fixes(sl_no)
            if not fixes:
                warn("No fixes to delete.")
                continue

            print("\n[ FIXES ]")
            for f in fixes:
                print(f"  id={f[0]} | vuln_id={f[2]} | {f[3][:80]}")

            fid = prompt("Enter fix id to delete: ")
            if not fid.isdecimal():
                error("Invalid id.")
                continue

            if confirm(f"Delete fix id={fid}?"):
                _apply_delete("Fix",
                              lambda _id=int(fid): delete_fix(_id, sl_no=sl_no))

        # ── DELETE EXPLOIT ────────────────────
        elif choice == "7":
            exploits = get_exploits(sl_no)
            if not exploits:
                warn("No exploits to delete.")
                continue

            print("\n[ EXPLOITS ]")
            for e in exploits:
                print(f"  id={e[0]} | {e[2]} | result: {e[5]}")

            eid = prompt("Enter exploit id to delete: ")
            if not eid.isdecimal():
                error("Invalid id.")
                continue

            if confirm(f"Delete exploit id={eid}?"):
                _apply_delete(
                    "Exploit",
                    lambda _id=int(eid): delete_exploit(_id, sl_no=sl_no))

        # ── ADD CORRECTION ────────────────────
        elif choice == "8":
            vulns = get_vulnerabilities(sl_no)
            if not vulns:
                warn("No vulnerabilities to correct.")
                continue

            print("\n[ VULNERABILITIES ]")
            for v in vulns:
                print(format_vulnerability_picker(v))

            vid = prompt("Enter vulnerability id to correct: ")
            if not vid.isdecimal():
                error("Invalid id.")
                continue

            # find the vuln for original text
            target_vuln = None
            for v in vulns:
                if v[0] == int(vid):
                    target_vuln = v
                    break
            if not target_vuln:
                error(f"Vulnerability id={vid} not found.")
                continue

            print("  Status options: hallucination / corrected / verified / downgraded / reclassified")
            status = prompt("Correction status: ").strip().lower()
            if status not in ("hallucination", "corrected", "verified", "downgraded", "reclassified"):
                error("Invalid status.")
                continue

            original = f"[{target_vuln[3]}] {target_vuln[2]}: {target_vuln[7]}"
            corrected = ""
            if status != "hallucination":
                corrected = prompt("Corrected finding (leave blank if N/A): ")
            reason = prompt("Reason / evidence: ")

            save_correction(sl_no, int(vid), status, original, corrected, reason)

        # ── EDIT CORRECTION ──────────────────
        elif choice == "9":
            corrections = get_corrections(sl_no)
            if not corrections:
                warn("No corrections recorded for this session.")
                continue

            print("\n[ CORRECTIONS ]")
            for cr in corrections:
                print(f"  id={cr[0]} | vuln_id={cr[2]} | {cr[3]} | {cr[6][:60]}")

            cid = prompt("Enter correction id to edit: ")
            if not cid.isdecimal():
                error("Invalid id.")
                continue

            print("  Fields: status / original_text / corrected_text / reason")
            field = prompt("Field to edit: ").strip()
            if field not in {"status", "original_text", "corrected_text", "reason"}:
                error("Invalid correction field.")
                continue
            value = prompt(f"New value for '{field}': ")
            _apply_edit(
                "Correction",
                lambda _id=int(cid), _field=field, _value=value: edit_correction(
                    _id, _field, _value, sl_no=sl_no))

        # ── DELETE CORRECTION ────────────────
        elif choice == "10":
            corrections = get_corrections(sl_no)
            if not corrections:
                warn("No corrections to delete.")
                continue

            print("\n[ CORRECTIONS ]")
            for cr in corrections:
                print(f"  id={cr[0]} | vuln_id={cr[2]} | {cr[3]} | {cr[6][:60]}")

            cid = prompt("Enter correction id to delete: ")
            if not cid.isdecimal():
                error("Invalid id.")
                continue

            if confirm(f"Delete correction id={cid}?"):
                _apply_delete(
                    "Correction",
                    lambda _id=int(cid): delete_correction(_id, sl_no=sl_no))

        # ── DELETE FULL SESSION ───────────────
        elif choice == "11":
            if confirm(f"\n\033[91mPermanently delete ENTIRE session SL# {sl_no} from all tables?\033[0m"):
                if not confirm("Confirm irreversible deletion of all session findings and reviews?"):
                    info("Deletion cancelled.")
                    continue
                try:
                    delete_full_session(sl_no)
                except Exception as exc:
                    error(f"Session deletion failed: {exc}")
                    continue
                success(f"Session SL# {sl_no} wiped.")
                return   # go back to main menu

        # ── BACK ──────────────────────────────
        elif choice == "12":
            break

        else:
            warn("Invalid choice.")
