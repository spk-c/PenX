"""Explainable finding prioritization with conservative ATT&CK hints.

ATT&CK is an adversary-behavior taxonomy, not a vulnerability classification.
A possible technique association never proves an actual attack took place.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
import threading
from penx_app.file_output import publish_unique, replace_config

from penx_app.app_paths import APP_ROOT
from penx_app.storage.db import get_session
from penx_app.domain.finding_policy import active_vulnerabilities

_OVERRIDE_FILE = APP_ROOT / "data" / "risk_overrides.json"
_OVERRIDE_LOCK = threading.RLock()
_WEIGHTS = {"critical": 90, "high": 72, "medium": 49, "low": 26,
            "info": 8, "unknown": 0}
_CONFIDENCE = {"confirmed": 1.0, "likely": 0.85, "possible": 0.65,
               "recommendation": 0.35}

# Only evidence strongly suggestive of adversary behavior is mapped.
# These are potential related techniques, not verified exploitation.
_TECHNIQUES = [
    (r"\bbrute[\s-]?force\b|\bpassword spraying\b", "T1110", "Brute Force"),
    (r"\bcredential dumping\b|\blsass\b", "T1003", "OS Credential Dumping"),
    (r"\bphishing\b", "T1566", "Phishing"),
    (r"\bpowershell\b.*(?:execution|abuse)|(?:execution|abuse).*powershell\b",
     "T1059.001", "PowerShell"),
    (r"\bsmb (?:relay|lateral movement)\b|\blateral movement (?:via|over) smb\b",
     "T1021.002", "SMB/Windows Admin Shares"),
    (r"\brdp (?:lateral movement|abuse)\b|\blateral movement via rdp\b",
     "T1021.001", "Remote Desktop Protocol"),
]


def assess_finding(row: tuple, override: dict | None = None) -> dict:
    """Report score only from recorded severity/confidence, never invented EPSS."""
    severity = str(row[3] or "unknown").lower()
    confidence = str(row[4] or "possible").lower()
    recommendation = confidence == "recommendation"
    calculated = (None if recommendation else round(_WEIGHTS.get(severity, 0) *
                       _CONFIDENCE.get(confidence, 0.65)))
    description = str(row[7] or "")
    words = (str(row[2] or "") + " " + description).lower()
    techniques = [
        {"id": tid, "name": name, "status": "candidate"}
        for pattern, tid, name in _TECHNIQUES if re.search(pattern, words, re.I)
    ]
    score = calculated
    status = "calculated"
    override = override or {}
    if recommendation and "score" in override:
        raise ValueError("Recommendations have task priorities, not vulnerability risk scores.")
    if "score" in override:
        val = override["score"]
        if not isinstance(val, int) or isinstance(val, bool) or not 0 <= val <= 100:
            raise ValueError("Risk score override must be an integer from 0 to 100.")
        score, status = val, "manual override"
    if recommendation and "techniques" in override:
        raise ValueError("Recommendations cannot be assigned attack techniques as vulnerability evidence.")
    if "techniques" in override:
        ids = override["techniques"]
        if not isinstance(ids, list) or len(ids) > 10 or any(
            not isinstance(t, str) or not re.fullmatch(r"T\d{4}(?:\.\d{3})?", t)
            for t in ids
        ):
            raise ValueError("ATT&CK IDs must look like T1110 or T1059.001.")
        techniques = [{"id": t, "name": "Manually assigned",
                       "status": "manual; verify applicability"} for t in ids]
    fix = str(override.get("priority") or "").strip().lower()
    if fix not in ("", "quick win", "planned"):
        raise ValueError("Priority must be quick win or planned.")
    if not fix:
        fix = "quick win" if (re.search(r"\b(patch|update|upgrade|disable|restrict|configure)\b",
                                            words) and score is not None and score >= 25) else "planned"
    return {
        "finding_id": row[0], "name": row[2], "severity": severity,
        "confidence": confidence, "status": ("recommendation" if recommendation else
            "confirmed finding" if confidence == "confirmed" else "potential finding"),
        "score": score, "score_source": ("not applicable" if recommendation else status),
        "calculated_score": calculated, "priority": fix,
        "techniques": techniques,
        "reason": ("Recommendations are hardening tasks, not validated vulnerabilities."
                   if recommendation else "Severity weight multiplied by recorded evidence confidence; "
                   "no CVSS, EPSS, KEV or internet exposure assumed."),
        "note": ("ATT&CK entries are possible behavior associations only, "
                 "not evidence of exploitation."),
    }


def _load_overrides(path: Path = _OVERRIDE_FILE) -> dict:
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Invalid risk override file.")
    return data


def save_override(session_id: int, finding_id: int, *,
                  score: int | None = None, techniques: list[str] | None = None,
                  priority: str | None = None, path: Path = _OVERRIDE_FILE) -> None:
    """Persist a reviewed local override after checking session ownership."""
    record = get_session(session_id)
    item = next((row for row in record.get("vulns", []) if row[0] == finding_id), None)
    if item is None:
        raise ValueError("Finding not present in selected scan session.")
    # Resolve the existing record under the same lock as the atomic write.
    # Previously a priority-only edit discarded the reviewed score and ATT&CK
    # technique selections for this finding.
    with _OVERRIDE_LOCK:
        if path.is_symlink() or (path.exists() and not path.is_file()):
            raise OSError("Refusing unsafe risk override destination")
        entries = _load_overrides(path)
        key = f"{session_id}:{finding_id}"
        previous = entries.get(key, {})
        if not isinstance(previous, dict):
            raise ValueError("Invalid stored risk override record.")
        override: dict[str, object] = dict(previous)
        if score is not None:
            override["score"] = score
        if techniques is not None:
            override["techniques"] = techniques
        if priority is not None:
            override["priority"] = priority
        assess_finding(item, override)  # validate the merged state before writing
        entries[key] = override
        replace_config(path, json.dumps(entries, indent=2, ensure_ascii=False) + "\n")


def assessment_for_session(session_id: int, *,
                           path: Path = _OVERRIDE_FILE) -> list[dict]:
    record = get_session(session_id)
    if not record.get("history"):
        raise ValueError("Unknown session.")
    entries = _load_overrides(path)
    return [assess_finding(item, entries.get(f"{session_id}:{item[0]}"))
            for item in active_vulnerabilities(record)]


def risk_report_json(session_id: int, directory: str | Path) -> Path:
    dest = Path(directory)
    dest.mkdir(parents=True, exist_ok=True)
    text = json.dumps({"session": session_id,
                       "assessments": assessment_for_session(session_id)},
                      indent=2, ensure_ascii=False) + "\n"
    return publish_unique(dest, f"risk_SL{int(session_id)}", ".json", text)
