#!/usr/bin/env python3
"""
PenX - db_evals.py
Evaluation CRUD, eval package export, and evaluation response parser.
"""

import re
import os
from penx_app.app_paths import APP_ROOT
from contextlib import closing
from datetime import datetime
from penx_app.storage.db import get_connection, save_correction, _assert_vulnerability_owner
from penx_app.storage.db_backend import VULNERABILITY_COLUMNS


# ─────────────────────────────────────────────
# EVALUATIONS CRUD
# ─────────────────────────────────────────────

def save_evaluation(sl_no: int, vuln_id: int, evaluator: str,
                    evidence_cited: str, verdict: str, confidence: str,
                    severity_correct: bool, cve_correct: bool,
                    software_correct: bool, fix_correct: bool,
                    notes: str) -> int:
    """Save an external evaluation record for a vulnerability."""
    with closing(get_connection()) as conn:
        c = conn.cursor()
        _assert_vulnerability_owner(c, sl_no, vuln_id)
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c.execute("""
            INSERT INTO evaluations
            (sl_no, vuln_id, evaluator, evidence_cited, verdict, confidence,
             severity_correct, cve_correct, software_correct, fix_correct,
             notes, evaluated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (sl_no, vuln_id, evaluator, evidence_cited, verdict, confidence,
              severity_correct, cve_correct, software_correct, fix_correct,
              notes, now))
        conn.commit()
        eid = c.lastrowid
        return eid


def get_evaluations(sl_no: int):
    with closing(get_connection()) as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM evaluations WHERE sl_no = %s ORDER BY evaluated_at", (sl_no,))
        rows = c.fetchall()
        return rows


def delete_evaluation(eval_id: int, *, sl_no: int):
    with closing(get_connection()) as conn:
        c = conn.cursor()
        c.execute("DELETE FROM evaluations WHERE id = %s AND sl_no = %s", (eval_id, sl_no))
        conn.commit()
        print(f"[+] Evaluation id={eval_id} deleted.")


# ─────────────────────────────────────────────
# EVAL PACKAGE EXPORT
# ─────────────────────────────────────────────

def export_eval_package(sl_no: int, output_dir: str = None) -> str:
    """Compatibility facade; rendering and files belong to reporting."""
    from penx_app.reporting.evaluation_packages import export_eval_package as export
    return export(sl_no, output_dir)



# ─────────────────────────────────────────────
# EVAL RESPONSE PARSER
# ─────────────────────────────────────────────

def parse_evaluation_response(sl_no: int, evaluator: str, response_text: str) -> list:
    """Store matched evaluations and their corrections in ONE transaction.

    Malformed or ambiguous reports are skipped as before. If any SQL write
    fails, no evaluation or correction from this import is committed.
    """
    from penx_app.domain.evaluation_parser import evaluation_groups

    groups = evaluation_groups(response_text)
    with closing(get_connection()) as conn:
        cursor = conn.cursor()
        try:
            cursor.execute(
                "SELECT id, vuln_name, severity, confidence, description "
                "FROM vulnerabilities WHERE sl_no = %s", (sl_no,)
            )
            vuln_rows = cursor.fetchall()
            by_name = {}
            for row in vuln_rows:
                by_name.setdefault((row[1] or "").casefold().strip(), []).append(row)

            saved_ids = []
            corrections_created = 0
            messages = []
            allowed_verdicts = {
                "valid", "hallucination", "corrected", "downgraded", "reclassified"
            }
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            for fields in groups:
                name = fields.get("EVAL", "").strip()
                verdict = fields.get("VERDICT", "").strip().lower()
                if verdict not in allowed_verdicts:
                    messages.append(
                        f"  [!] Invalid evaluation verdict {verdict!r} for {name!r}; skipping"
                    )
                    continue
                matches = by_name.get(name.casefold(), [])
                if len(matches) != 1:
                    messages.append(
                        f"  [!] Expected exactly one finding named {name!r}; "
                        f"got {len(matches)}. Skipping to avoid incorrect linkage."
                    )
                    continue
                finding = matches[0]
                vuln_id = finding[0]
                # Unknown correctness is not an explicit 'no'. Reject a whole
                # incomplete group instead of writing four false judgments.
                required = ("SEVERITY_CORRECT", "CVE_CORRECT",
                            "SOFTWARE_CORRECT", "FIX_CORRECT")
                flags = {key: fields.get(key, "").strip().lower() for key in required}
                if any(value not in {"yes", "no"} for value in flags.values()):
                    messages.append(f"  [!] Missing/invalid correctness field for {name!r}; skipping")
                    continue
                correctness = tuple(flags[key] == "yes" for key in required)
                confidence = fields.get("CONFIDENCE", "medium").strip().lower()
                if confidence not in {"low", "medium", "high"}:
                    confidence = "medium"
                evidence = fields.get("EVIDENCE", "none cited").strip()
                notes = fields.get("NOTES", "").strip()
                identity = (sl_no, vuln_id, evaluator, evidence, verdict,
                            confidence, *correctness, notes)
                cursor.execute(
                    "SELECT id FROM evaluations WHERE sl_no = %s AND vuln_id = %s "
                    "AND evaluator = %s AND evidence_cited = %s AND verdict = %s "
                    "AND confidence = %s AND severity_correct = %s AND cve_correct = %s "
                    "AND software_correct = %s AND fix_correct = %s AND notes = %s",
                    identity,
                )
                if cursor.fetchone() is not None:
                    messages.append(f"  [*] Duplicate evaluation for {name!r}; skipping")
                    continue
                cursor.execute(
                    "INSERT INTO evaluations "
                    "(sl_no, vuln_id, evaluator, evidence_cited, verdict, confidence, "
                    "severity_correct, cve_correct, software_correct, fix_correct, "
                    "notes, evaluated_at) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                    (*identity, now),
                )
                saved_ids.append(cursor.lastrowid)
                messages.append(
                    f"  [+] Saved eval for {name!r} (vuln #{vuln_id}): "
                    f"{verdict} [{confidence}]"
                )
                if verdict != "valid":
                    original = f"[{finding[2]}] {finding[1]}: {(finding[4] or '')[:200]}"
                    reason = f"External eval by {evaluator} [{confidence} confidence]"
                    if notes:
                        reason += f" | {notes[:300]}"
                    if evidence:
                        reason += f" | Evidence: {evidence[:200]}"
                    cursor.execute(
                        "INSERT INTO corrections "
                        "(sl_no, vuln_id, status, original_text, corrected_text, "
                        "reason, corrected_at) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                        (sl_no, vuln_id, verdict, original, "", reason, now),
                    )
                    corrections_created += 1
            conn.commit()
        except BaseException:
            # Includes an interactive Ctrl+C: prior successful inserts must
            # never leak into persistent history as a partial reviewer import.
            conn.rollback()
            raise

    # Report success only after the storage transaction has committed.
    for message in messages:
        print(message)
    if corrections_created:
        print(f"  [+] Auto-created {corrections_created} correction(s) from evaluation verdicts")
    overall_risk = re.search(
        r"OVERALL_RISK_LEVEL:\s*(CRITICAL|HIGH|MEDIUM|LOW)", response_text, re.IGNORECASE
    )
    halluc_count = re.search(r"HALLUCINATION_COUNT:\s*(\d+)", response_text, re.IGNORECASE)
    accuracy_summary = re.search(
        r"ACCURACY_SUMMARY:\s*(.+?)(?:\n|$)", response_text, re.IGNORECASE
    )
    if overall_risk:
        print(f"  [*] Evaluator risk assessment: {overall_risk.group(1).upper()}")
    if halluc_count:
        print(f"  [*] Hallucinations found: {halluc_count.group(1)}")
    if accuracy_summary:
        print(f"  [*] Accuracy summary: {accuracy_summary.group(1).strip()}")
    return saved_ids



# ─────────────────────────────────────────────
# LEARNED RULES — distilled from corrections
# ─────────────────────────────────────────────

def save_learned_rule(rule_text: str, source: str) -> int:
    """Save a single distilled rule."""
    with closing(get_connection()) as conn:
        c = conn.cursor()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        c.execute("""
            INSERT INTO learned_rules (rule_text, source, created_at)
            VALUES (%s, %s, %s)
        """, (rule_text, source, now))
        conn.commit()
        rid = c.lastrowid
        return rid


def get_learned_rules():
    with closing(get_connection()) as conn:
        c = conn.cursor()
        c.execute("SELECT id, rule_text, source, created_at FROM learned_rules ORDER BY id")
        rows = c.fetchall()
        return rows


def clear_learned_rules():
    """Remove all learned rules (before importing a fresh distillation)."""
    with closing(get_connection()) as conn:
        c = conn.cursor()
        c.execute("DELETE FROM learned_rules")
        conn.commit()


def export_distillation_package(output_dir: str = None) -> str:
    """Compatibility facade; rendering and files belong to reporting."""
    from penx_app.reporting.evaluation_packages import export_distillation_package as export
    return export(output_dir)



def parse_distilled_rules(response_text: str) -> list[str]:
    """Legacy public API; the parser is pure and owned by the domain."""
    from penx_app.domain.evaluation_parser import parse_distilled_rules as parse
    return parse(response_text)


def import_distilled_rules(source: str, response_text: str) -> list:
    """Atomically replace stored rules, but only after full validation.

    Caller must review and confirm new rules before invoking this function.
    Imported text is not trusted system policy, only advisory feedback.
    """
    rules = parse_distilled_rules(response_text)
    if not rules:
        print('[!] No valid RULE: lines found; existing rules preserved.')
        return []
    conn = get_connection()
    try:
        c = conn.cursor()
        c.execute('DELETE FROM learned_rules')
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        ids = []
        for rule in rules:
            c.execute('INSERT INTO learned_rules (rule_text, source, created_at) VALUES (%s, %s, %s)',
                      (rule, source, now))
            ids.append(c.lastrowid)
        conn.commit()
        return ids
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
