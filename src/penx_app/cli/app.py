"""Terminal application: dialogs compose the independent application services."""
import os
import sys
from pathlib import Path as Path
from penx_app.cli import cli_views
from penx_app.application.scan_recovery import save_unanalysed_recon, save_unsaved_assessment
from penx_app.reporting.export import export_menu as export_menu
from penx_app.reporting.report_management import generate_session_reports, generate_session_reports_independent as generate_session_reports_independent, existing_reports as existing_reports, delete_session_reports as delete_session_reports, publication_status as publication_status
from penx_app.cli.cli_navigation import is_back, show_back, navigation_input
from penx_app.config import DB_ENGINE
from penx_app.storage.db import get_connection, create_session, save_vulnerability as save_vulnerability, save_fix as save_fix, save_exploit as save_exploit, save_summary as save_summary, save_correction as save_correction, save_assessment, RISK_LEVELS as RISK_LEVELS, get_all_history, get_session, get_vulnerabilities as get_vulnerabilities, get_fixes as get_fixes, get_exploits as get_exploits, get_corrections as get_corrections, edit_vulnerability as edit_vulnerability, edit_fix as edit_fix, edit_exploit as edit_exploit, edit_summary_risk as edit_summary_risk, edit_correction as edit_correction, delete_vulnerability as delete_vulnerability, delete_exploit as delete_exploit, delete_fix as delete_fix, delete_correction as delete_correction, delete_full_session
from penx_app.cli.db_display import print_history as print_history, print_session
from penx_app.storage.db_evals import get_evaluations as get_evaluations, delete_evaluation as delete_evaluation, parse_evaluation_response as parse_evaluation_response, import_distilled_rules as import_distilled_rules, parse_distilled_rules as parse_distilled_rules, get_learned_rules as get_learned_rules
from penx_app.reporting.evaluation_packages import export_eval_package as export_eval_package, export_distillation_package as export_distillation_package
from penx_app.storage.db_training import export_training_data as export_training_data
from penx_app.scanners.tools import interactive_tool_run, format_recon_for_llm as format_recon_for_llm, run_default_recon as run_default_recon, recon_has_evidence, ReconChoice
from penx_app.analysis.llm import analyse_target
from penx_app.reporting.scan_coverage import coverage
from penx_app.cli.console_ui import badge, phase
from penx_app.app_paths import APP_ROOT
from penx_app.analysis.llm_client import fetch_models, explain_http_error
import requests
from penx_app.runtime_options import RuntimeOptions, runtime_options, live_output, toggle_live_output


# ─────────────────────────────────────────────
# BANNER
# ─────────────────────────────────────────────

def banner():
    return cli_views.banner()

def divider(label=""):
    return cli_views.divider(label)

def prompt(text, *, navigation: bool = False):
    colored = f"\033[36m{text}\033[0m"
    return (navigation_input(colored) if navigation else input(colored)).strip()


def success(text):
    return cli_views.success(text)

def warn(text):
    return cli_views.warn(text)

def error(text):
    return cli_views.error(text)

def _apply_edit(label: str, operation) -> None:
    """Safely report a scoped edit, including missing rows and DB failures."""
    try:
        updated = operation()
    except ValueError as exc:
        error(str(exc))
    except Exception as exc:
        error(f"Could not update {label.lower()}: {type(exc).__name__}: {exc}")
    else:
        if updated:
            success(f"{label} updated.")
        else:
            warn(f"No {label.lower()} row was updated for this session.")


def _apply_delete(label: str, operation) -> None:
    """Report a scoped delete accurately; failed or missing rows are not successes."""
    try:
        removed = operation()
    except ValueError as exc:
        error(str(exc))
    except Exception as exc:
        error(f"Could not delete {label.lower()}: {type(exc).__name__}: {exc}")
    else:
        if removed:
            success(f"{label} deleted.")
        else:
            warn(f"No {label.lower()} row was deleted for this session.")


def info(text):
    return cli_views.info(text)

def confirm(question: str) -> bool:
    ans = prompt(f"{question} [y/N]: ").lower()
    return ans in ("y", "yes", "j", "ja")


# ─────────────────────────────────────────────
# NEW SCAN
# ─────────────────────────────────────────────

def llm_auth_preflight() -> bool:
    """Abort before scanning if the local model registry rejects credentials.

    Missing/unsupported /v1/models must not block explicit-model backends:
    the actual chat request still validates authentication later.
    """
    from penx_app.config import LLM_MODELS_URL, LLM_API_KEY
    try:
        fetch_models(LLM_MODELS_URL, api_key=LLM_API_KEY, timeout=4)
    except requests.exceptions.HTTPError as exc:
        if getattr(exc.response, "status_code", None) in (401, 403):
            warn(explain_http_error(exc))
            warn("No scan started. Correct your local LLM credentials and restart PenX.")
            return False
    except (requests.exceptions.RequestException, ValueError):
        pass
    return True


def preserve_failed_recon(session_id: int, raw_scan: str):
    return save_unanalysed_recon(APP_ROOT, session_id, raw_scan)

def preserve_failed_assessment(session_id: int, result: dict):
    return save_unsaved_assessment(APP_ROOT, session_id, result, notify=warn)

def _discard_failed_scan(sl_no: int, raw_scan: str) -> None:
    """Retain scan evidence and clean up best-effort without masking the failure."""
    try:
        path = preserve_failed_recon(sl_no, raw_scan)
        warn(f"Raw recon retained locally: {path} (not a completed assessment).")
    except OSError as save_exc:
        warn(f"Could not preserve raw recon: {save_exc}")
    try:
        delete_full_session(sl_no)
    except Exception as delete_exc:
        warn(f"Could not remove pending session SL#{sl_no}: {delete_exc}. "
             "Remove it manually when the database is available.")


def _recon_choice_menu(target: str, scan_passive_only: bool) -> tuple[str | None, bool]:
    """Run the recon tool picker (or passive-only recon) for a target.

    Shared by the full scan flow and the recon-only menu step. The picker
    owns the tool choice and active-scan consent; the caller decides what
    happens to the collected evidence (assessment or display only). Returns
    the raw scan text and whether passive-only sources were used.
    Interruptions and tool failures propagate to the caller.
    """
    phase("MODE", "Passive external-source collection" if scan_passive_only
          else "Choose scanner(s) or passive-only recon")
    # In passive mode, no scanner or direct target HTTP request is made.
    divider("PASSIVE THIRD-PARTY SOURCES" if scan_passive_only else "RECON / TOOL SELECTION")
    if not scan_passive_only:
        info("Choose recon tools to run:")
    else:
        info("Source lookups are sent to DNS/CT/RDAP providers (and configured indexes).")
        info("No direct target connections or model-requested active tools.")
    if scan_passive_only:
        from penx_app.scanners.passive_recon import passive_recon
        raw_scan = passive_recon(target)
        print(raw_scan)
        return raw_scan, True
    selection = interactive_tool_run(target)
    if selection is ReconChoice.PASSIVE_ONLY:
        info("Passive-only selected. Third-party DNS/CT/RDAP/index lookups only.")
        info("No direct target connections or model-requested active tools.")
        from penx_app.scanners.passive_recon import passive_recon
        raw_scan = passive_recon(target)
        print(raw_scan)
        return raw_scan, True
    return selection, False


def new_scan(*, passive_only: bool = False) -> bool:
    """Legacy bool API; the menu consumes the richer per-scan outcome."""
    return _execute_scan(passive_only=passive_only).completed


def _execute_scan(*, passive_only: bool = False):
    from penx_app.application.scan_outcome import ScanOutcome
    scan_passive_only = passive_only
    divider("PASSIVE RECON" if scan_passive_only else "NEW SCAN")
    show_back()
    print()
    target = prompt("[?] Enter target IP or domain: ", navigation=True)
    if is_back(target):
        info("Returning to main menu; no scan started.")
        return ScanOutcome(False, False, "cancelled")
    if not target:
        warn("No target entered.")
        return ScanOutcome(False, False, "invalid_target")
    if not llm_auth_preflight():
        return ScanOutcome(False, False, "model_preflight")

    # check if target was scanned before
    history = get_all_history()
    past = [row for row in history if row[1] == target]
    if past:
        warn(f"Target '{target}' has been scanned before ({len(past)} time(s)).")
        if not confirm("Continue with a new scan?"):
            return ScanOutcome(False, False, "cancelled")

    # Create the session only after recon was selected and completed.
    # A user backing out at the scanner menu must not create history rows.
    # A selected scan can fail after recon; keep its diagnostic visible.
    # The selected scan now owns its error/acknowledgement state; no module flag.
    try:
        raw_scan, scan_passive_only = _recon_choice_menu(target, scan_passive_only)
    except (KeyboardInterrupt, EOFError) as exc:
        warn(f"Scan interrupted: {exc}. No session created.")
        return ScanOutcome(False, True, "interrupted")
    except Exception as exc:
        warn(f"Recon failed ({type(exc).__name__}): {exc}. No session created.")
        return ScanOutcome(False, True, "recon_failed")

    if raw_scan is None:
        info("Returning to main menu; no scan or session created.")
        return ScanOutcome(False, False, "cancelled")
    if not recon_has_evidence(raw_scan, passive_only=scan_passive_only):
        warn("No usable scan evidence: all selected scanners or external sources "
             "failed or returned diagnostics. No completed assessment created.")
        return ScanOutcome(False, True, "no_evidence")

    scan_coverage = coverage(raw_scan, passive_only=scan_passive_only)
    if scan_coverage["status"] == "PARTIAL":
        warn("PARTIAL scan coverage: failed adapters: " + ", ".join(scan_coverage["failed"]))
    from penx_app.application.assessment_service import AssessmentPorts, run_assessment
    from penx_app.config import MODEL_NAME

    def notify(event, value):
        if event == 'reserved':
            info(f"Assessment session reserved — SL# {value} (pending until committed)")
            phase("RECON", "Source collection complete")
            divider("AI ANALYSIS")
        elif event == 'reservation_failed':
            warn(f"Could not reserve an assessment session ({type(value).__name__}): {value}. No session created.")
        elif event == 'cleanup_failed':
            warn(f"Could not remove the pending session ({type(value).__name__}): {value}. "
                 "Review pending records when the database is available.")
        elif event == 'analysis_failed':
            warn(f"Analysis interrupted or failed ({type(value).__name__}): {value}. No completed assessment was saved.")
        elif event == 'saving':
            divider("SAVING TO DATABASE")
        elif event == 'save_failed':
            warn(f"Assessment save failed: {value}. Rolling back the session.")
        elif event == 'backup_failed':
            warn(f"Unable to preserve unsaved model assessment: {type(value).__name__}: {value}")
        elif event == 'saved':
            session_id, counts, result = value
            success("Saved " + str(counts["vulnerabilities"]) + " findings, " +
                    str(counts["recommendations"]) + " recommendations, " +
                    str(counts.get("rejected", 0)) + " rejected/audit-only, " +
                    str(counts["corrections"]) + " correction(s), " +
                    str(counts["exploits"]) + " exploit record(s).")
            success(f"All data saved. SL# {session_id} | Risk: {badge(result['risk_level'])} | Coverage: {scan_coverage['status']}")
        elif event == 'exported':
            success("Automatic reports created:")
            for kind, path in value.items():
                success(f"  {kind.upper()}: {path}")
        elif event == 'export_failed':
            warn(f"Automatic HTML/PDF export failed ({type(value).__name__}: {value}). "
                 "The completed scan remains saved; use View History to retry.")

    outcome = run_assessment(target, raw_scan, scan_coverage,
        passive_only=scan_passive_only, model_name=MODEL_NAME,
        ports=AssessmentPorts(create_session, analyse_target, save_assessment,
            _discard_failed_scan, preserve_failed_assessment, generate_session_reports, notify))
    if not outcome.completed:
        return ScanOutcome(False, True, outcome.stage, session_id=outcome.session_id)
    if outcome.session_id is None:
        warn("Completed assessment did not return a valid session identifier.")
        return ScanOutcome(False, True, "invalid-session")
    sl_no = outcome.session_id
    divider()

    # Follow-up UI failures must never undo an already committed assessment.
    try:
        data = get_session(sl_no)
        print_session(data)
        from penx_app.application.risk_assessment import assessment_for_session
        for finding in assessment_for_session(sl_no):
            score_label = (f"{finding['score']}/100" if finding["score"] is not None else "N/A")
            print(f"  [RISK] {finding['name']}: {score_label} "
                  f"({finding['score_source']}); {finding['priority']}")
        from penx_app.cli.assessment_ui import automatic_regression_check
        automatic_regression_check(sl_no)
        if confirm("Edit or delete anything in this session?"):
            edit_delete_menu(sl_no)
    except Exception as exc:
        warn(f"Assessment is saved, but follow-up display/review failed: "
             f"{type(exc).__name__}: {exc}")
    return ScanOutcome(True, True, "completed", session_id=sl_no)


def run_recon_only() -> None:
    """Run the recon tool picker without reserving a session or model analysis.

    The collected evidence is displayed in place; no database session is
    reserved, nothing is saved and the model is never queried, so no
    model-credential preflight applies.
    """
    divider("RECON ONLY")
    show_back()
    print()
    target = prompt("[?] Enter target IP or domain: ", navigation=True)
    if is_back(target):
        info("Returning to main menu; no recon started.")
        return
    if not target:
        warn("No target entered.")
        return
    # Recon-only never opens the assessment database. This also works if a
    # legacy SQLite upgrade is blocked or an optional MariaDB server is down.
    # The active scanner picker still enforces target scope and consent.
    try:
        raw_scan, passive_used = _recon_choice_menu(target, scan_passive_only=False)
    except (KeyboardInterrupt, EOFError) as exc:
        warn(f"Recon interrupted: {exc}. No session created.")
        return
    except Exception as exc:
        warn(f"Recon failed ({type(exc).__name__}): {exc}. No session created.")
        return
    if raw_scan is None:
        info("Returning to main menu; no session created.")
        return
    # The passive picker has already displayed its output. Active scanner
    # results are returned by the formatter and must be shown here.
    if not passive_used:
        print(raw_scan)
    print()
    success("Recon complete. No session or assessment created.")


# ─────────────────────────────────────────────
# VIEW HISTORY
# ─────────────────────────────────────────────

def _session_is_active(history) -> bool:
    return cli_views.is_active_session(history)

def view_history():
    """Public compatible entrypoint; capture patched dependencies per call."""
    from penx_app.cli.history_dialog import view_history as run
    return run(**{
        name: globals()[name] for name in ["divider","get_all_history","warn","print_history","show_back","prompt","is_back","error","get_session","_session_is_active","print_session","existing_reports","info","generate_session_reports","generate_session_reports_independent","success","confirm","delete_session_reports","edit_delete_menu","delete_full_session","publication_status"]
    })


# ─────────────────────────────────────────────
# EDIT / DELETE MENU
# ─────────────────────────────────────────────

def format_vulnerability_picker(row: tuple) -> str:
    return cli_views.format_vulnerability_picker(row)

def edit_delete_menu(sl_no: int):
    """Public compatible entrypoint; capture patched dependencies per call."""
    from penx_app.cli.session_edit_dialog import edit_delete_menu as run
    return run(sl_no, **{
        name: globals()[name] for name in ["divider","show_back","prompt","is_back","warn","error","success","confirm","_apply_edit","_apply_delete","info","format_vulnerability_picker","RISK_LEVELS","get_vulnerabilities","get_fixes","get_exploits","get_corrections","edit_vulnerability","edit_fix","edit_exploit","edit_summary_risk","delete_vulnerability","delete_fix","delete_exploit","save_correction","edit_correction","delete_correction","delete_full_session"]
    })


# ─────────────────────────────────────────────
# DB CONNECTION CHECK
# ─────────────────────────────────────────────

def check_db():
    try:
        conn = get_connection()
        conn.close()
        return True
    except Exception as e:
        error(f"{DB_ENGINE.upper()} database connection failed: {e}")
        if DB_ENGINE == "mariadb":
            error("Start MariaDB and check the PENX_DB_* settings in .env")
        else:
            error("Check write access to PENX_DB_PATH in .env")
        return False


def review_menu_choice(choice: str) -> None:
    """Dispatch review menus with the legacy penx patch points preserved."""
    from penx_app.cli.evaluation_dialog import handle_review_choice
    return handle_review_choice(choice, **{
        name: globals()[name] for name in ["divider","info","warn","error","success","prompt","get_all_history","print_history","export_eval_package","parse_evaluation_response","export_training_data","get_learned_rules","export_distillation_package","parse_distilled_rules","confirm","import_distilled_rules"]
    })


# ─────────────────────────────────────────────
# MAIN MENU
# ─────────────────────────────────────────────

def main_menu():
    """Exit gracefully when the user cancels any nested prompt."""
    try:
        with runtime_options(RuntimeOptions(live_output())):
            _main_menu_loop()
    except (KeyboardInterrupt, EOFError):
        print("\n[*] PenX interrupted — shutting down cleanly.")
        return


def _main_menu_loop():
    while True:
        banner()
        print("  \033[92m[1]\033[0m  New Scan")
        print("  \033[92m[14]\033[0m  Run Recon Tools (no assessment)")
        print("  \033[92m[2]\033[0m  View History")
        print("  \033[92m[3]\033[0m  Export Eval Package")
        print("  \033[92m[4]\033[0m  Import Evaluation")
        print("  \033[92m[5]\033[0m  Export Training Data")
        print("  \033[92m[6]\033[0m  Distill Rules (external LLM)")
        print("  \033[92m[7]\033[0m  Import Distilled Rules")
        print("  \033[92m[9]\033[0m  Scan Diff & Trends")
        print("  \033[92m[10]\033[0m Risk + MITRE ATT&CK Review")
        mode = "LIVE" if live_output() else "QUIET"
        print(f"  \033[92m[11]\033[0m Terminal Output: {mode}")
        print("  \033[92m[12]\033[0m Local AI Setup / Reconfigure")
        print("  \033[92m[13]\033[0m Check for Updates")
        print("  \033[92m[8]\033[0m  Exit")
        divider()

        choice = prompt("penx> ")

        if choice == "1":
            # Do not clear the console after a failed/partial scan: the error
            # and recovery path must remain visible until acknowledged.
            outcome = _execute_scan()
            if outcome.acknowledge:
                input("\n\033[90mPress Enter to return to main menu...\033[0m")

        elif choice == "14":
            # Recon-only: the tool picker runs and its evidence is shown,
            # but no session is reserved and the model is never queried.
            run_recon_only()
            input("\n\033[90mPress Enter to continue...\033[0m")

        elif choice == "2":
            view_history()
            input("\n\033[90mPress Enter to continue...\033[0m")

        elif choice in {"3", "4", "5", "6", "7"}:
            review_menu_choice(choice)

        elif choice == "9":
            from penx_app.cli.assessment_ui import compare_menu
            compare_menu()
            input("\n\033[90mPress Enter to continue...\033[0m")

        elif choice == "10":
            from penx_app.cli.assessment_ui import risk_menu
            risk_menu()
            input("\n\033[90mPress Enter to continue...\033[0m")

        elif choice == "11":
            # Runtime setting shared by scanner and model output in this session.
            is_live = toggle_live_output()
            success("Terminal output: " + ("LIVE" if is_live else "QUIET"))
            input("\n\033[90mPress Enter to continue...\033[0m")

        elif choice == "12":
            from penx_app.setup.llm_setup import maybe_configure_llm
            if maybe_configure_llm(force=True):
                info("Restart PenX to use the new model settings in this session.")
                input("\n\033[90mPress Enter to close PenX...\033[0m")
                return
            input("\n\033[90mPress Enter to continue...\033[0m")

        elif choice == "13":
            from penx_app.updates import update_interactive
            if update_interactive():
                # The interactive installer runs only after PenX exits.
                return
            input("\n\033[90mPress Enter to continue...\033[0m")

        elif choice == "8":
            print("\n\033[91m[*] Shutting down PenX. Stay legal.\033[0m\n")
            sys.exit(0)

        else:
            warn("Invalid choice.")


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────

def main():
    if os.name == "nt":
        try:
            import ctypes
            handle = ctypes.windll.kernel32.GetStdHandle(-11)
            mode = ctypes.c_uint32()
            if ctypes.windll.kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                ctypes.windll.kernel32.SetConsoleMode(handle, mode.value | 0x0004)
        except Exception:
            pass
        for stream in (sys.stdout, sys.stderr):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except (AttributeError, OSError):
                pass
    if os.name == "nt" and getattr(sys, "frozen", False):
        # Explicit user consent is required before fetching/installing tools.
        # --version and --setup-status bypass this first-launch path.
        from penx_app.setup.first_run_setup import run_setup
        run_setup()
    if not check_db():
        sys.exit(1)
    from penx_app.updates import startup_notice
    startup_notice()
    main_menu()
