"""External evaluator and rule-distillation dialogs.

All reads/writes are passed from the application entrypoint at call time.
Imported LLM text is treated as user-supplied review material, not code.
"""
from __future__ import annotations


def handle_review_choice(choice: str, *, divider, info, warn, error, success, prompt, get_all_history, print_history, export_eval_package, parse_evaluation_response, export_training_data, get_learned_rules, export_distillation_package, parse_distilled_rules, confirm, import_distilled_rules):
    if choice == "3":
        divider("EXPORT EVAL PACKAGE")
        info("Exports a scan session as a review package for external LLM evaluation.")
        rows = get_all_history()
        if not rows:
            warn("No scans in database yet.")
        else:
            print_history(rows)
            sl_str = prompt("Enter SL# to export: ")
            if sl_str.isdigit():
                path = export_eval_package(int(sl_str))
                if path:
                    success(f"Eval package ready: {path}")
                    info("Paste the contents into Claude Code or another LLM for review.")
                    info("Then use [4] Import Evaluation to store the response.")
            else:
                error("Invalid SL#.")
        input("\n\033[90mPress Enter to continue...\033[0m")

    elif choice == "4":
        divider("IMPORT EVALUATION")
        info("Paste an external LLM's evaluation response to store it.")
        sl_str = prompt("Enter SL# this evaluation is for: ")
        if not sl_str.isdigit():
            error("Invalid SL#.")
        else:
            sl_no = int(sl_str)
            evaluator = prompt("Evaluator name (e.g., claude-opus-4-6, gpt-5-4): ")
            if not evaluator:
                evaluator = "unknown"
            print("\nPaste the evaluation response below.")
            print("When done, enter a line with just 'END' to finish.\n")
            response_lines = []
            while True:
                line = input()
                if line.strip() == "END":
                    break
                response_lines.append(line)
            response_text = "\n".join(response_lines)
            if response_text.strip():
                saved = parse_evaluation_response(sl_no, evaluator, response_text)
                if saved:
                    success(f"Saved {len(saved)} evaluation(s) for SL#{sl_no}")
                else:
                    warn("No evaluations could be parsed from the response.")
            else:
                warn("Empty response. Nothing saved.")
        input("\n\033[90mPress Enter to continue...\033[0m")

    elif choice == "5":
        divider("EXPORT TRAINING DATA")
        info("Exports corrected sessions as JSONL for fine-tuning.")
        info("Only sessions with corrections are included.")
        path = export_training_data()
        if path:
            success(f"Training data ready: {path}")
        input("\n\033[90mPress Enter to continue...\033[0m")

    elif choice == "6":
        divider("DISTILL RULES")
        info("Exports all corrections as a distillation package for an external LLM.")
        existing = get_learned_rules()
        if existing:
            info(f"Currently {len(existing)} learned rule(s) in database.")
        path = export_distillation_package()
        if path:
            success(f"Distillation package ready: {path}")
            info("Paste the contents into Claude Code or another LLM.")
            info("Then use [7] Import Distilled Rules to store the RULE: lines.")
        input("\n\033[90mPress Enter to continue...\033[0m")

    elif choice == "7":
        divider("IMPORT DISTILLED RULES")
        info("Paste an external LLM's distilled rules to replace the current rule set.")
        existing = get_learned_rules()
        if existing:
            warn(f"This will REPLACE the current {len(existing)} learned rule(s).")
        source = prompt("Source name (e.g., claude-opus-4-6): ")
        if not source:
            source = "unknown"
        print("\nPaste the distilled rules below.")
        print("When done, enter a line with just 'END' to finish.\n")
        response_lines = []
        while True:
            line = input()
            if line.strip() == "END":
                break
            response_lines.append(line)
        response_text = "\n".join(response_lines)
        if response_text.strip():
            proposed = parse_distilled_rules(response_text)
            if proposed:
                print(f"\n[ REVIEW {len(proposed)} PROPOSED RULE(S) ]")
                for i, rule in enumerate(proposed, 1):
                    print(f"  {i}. {rule}")
            if proposed and confirm('Replace existing rules with this exact set?'):
                saved = import_distilled_rules(source, response_text)
            else:
                saved = []
                warn('Rules not imported. Previous set preserved.')
            if saved:
                success(f"Imported {len(saved)} learned rule(s) from {source}")
            else:
                warn("No RULE: lines found in the response.")
        else:
            warn("Empty response. Nothing saved.")
        input("\n\033[90mPress Enter to continue...\033[0m")
