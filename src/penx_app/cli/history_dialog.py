"""History and report management dialog. Only injected presentation/service ports."""
from __future__ import annotations

def view_history(*, divider, get_all_history, warn, print_history, show_back, prompt, is_back, error, get_session, _session_is_active, print_session, existing_reports, info, generate_session_reports, generate_session_reports_independent, success, confirm, delete_session_reports, edit_delete_menu, delete_full_session, publication_status=None):
    divider("SCAN HISTORY")
    rows = get_all_history()
    if not rows:
        warn("No scans in database yet.")
        return

    print_history(rows)
    show_back()
    sl_no_str = prompt("Enter SL# to manage (Enter/Esc=Back): ", navigation=True)
    if not sl_no_str or is_back(sl_no_str):
        return
    if not sl_no_str.isdecimal() or int(sl_no_str) <= 0:
        error("Invalid SL#.")
        return
    sl_no = int(sl_no_str)
    data = get_session(sl_no)
    if not _session_is_active(data.get("history")):
        error(f"SL# {sl_no} not found.")
        return

    target = data["history"][1]
    print_session(data)

    while True:
        divider(f"HISTORY / REPORTS — SL# {sl_no}")
        try:
            files = existing_reports(sl_no, target)
        except OSError as exc:
            warn(f"Cannot inspect saved reports: {exc}")
            files = {}
        if publication_status is not None:
            try:
                state = publication_status(sl_no, target)
            except OSError as exc:
                warn(f"Cannot inspect report publication state: {exc}")
            else:
                if state == "in_progress":
                    warn("A previous report export was interrupted. HTML/PDF may "
                         "contain different revisions; choose [1] to regenerate.")
                elif state == "partial":
                    warn("A prior report export was incomplete. Review saved files "
                         "and choose [1] to retry any missing formats.")
        if files:
            for fmt, path in files.items():
                info(f"Saved {fmt.upper()}: {path}")
        else:
            info("No HTML/PDF files currently saved for this session.")

        print("  [1] Export / regenerate HTML and PDF")
        print("  [2] Delete saved HTML/PDF reports (keep scan history)")
        print("  [3] Edit findings / delete individual records")
        print("  [4] Delete FULL scan session and its HTML/PDF reports")
        print("  [0] Back")
        show_back()
        choice = prompt("Choice (Esc=Back): ", navigation=True)
        if not choice or is_back(choice):
            return

        if choice == "1":
            try:
                published = generate_session_reports_independent(sl_no)
                for fmt, path in published.created.items():
                    success(f"{fmt.upper()} created: {path}")
                for fmt, failure in published.failed.items():
                    warn(f"{fmt.upper()} export failed: {failure}; existing exports remain saved.")
            except Exception as exc:
                warn(f"Could not export reports: {type(exc).__name__}: {exc}")
        elif choice == "2":
            if not files:
                warn("No saved HTML/PDF reports to delete.")
                continue
            if confirm(f"Delete {len(files)} HTML/PDF file(s) for SL#{sl_no}? Database data stays saved."):
                try:
                    deleted = delete_session_reports(sl_no, target)
                    success(f"Deleted {len(deleted)} report file(s). Scan history was kept.")
                except OSError as exc:
                    warn(f"Could not delete all report files: {exc}")
        elif choice == "3":
            edit_delete_menu(sl_no)
            data = get_session(sl_no)
            if not data["history"]:
                info("Scan session was deleted.")
                return
        elif choice == "4":
            if confirm(f"Permanently delete SL#{sl_no} and ALL its database records?"):
                if confirm("Also delete its saved HTML/PDF files? This cannot be undone."):
                    try:
                        # Delete database history only after explicit double confirmation.
                        delete_full_session(sl_no)
                    except Exception as exc:
                        error(f"Database deletion failed: {exc}")
                        continue
                    try:
                        deleted = delete_session_reports(sl_no, target)
                        success(f"Removed {len(deleted)} HTML/PDF report file(s).")
                    except OSError as exc:
                        warn(f"Session deleted, but some report files remain: {exc}")
                    return
                info("Deletion cancelled.")
        else:
            warn("Invalid choice.")
