"""Source-grounded, bounded feature-request triage.

No code is executed or imported from the repository. Only allowlisted local
production files are inspected. A positive match proves a code fragment exists,
NOT that the complete proposed feature or its runtime behavior is verified.
"""
from __future__ import annotations

from pathlib import Path
import re
if __package__:
    from .source_layout import SOURCE_PATHS
else:
    from source_layout import SOURCE_PATHS

MAX_TOPICS = 8
MAX_SOURCE_FILES = 200
MAX_SOURCE_SIZE = 180_000

# Each signal matches a specific source implementation rather than prose, issue
# text, test fixtures, or LLM-generated claims. The root is examined at runtime;
# missing or renamed modules never become invented source citations.
FEATURES = {
    "structured": {
        "match": r"structured|scanner output|nmap.{0,12}xml|nikto.{0,12}json|parsers?",
        "signals": (
            ("src/tools.py", r"args\.extend\(\['-oX',"),
            ("src/cve_observations.py", r"^def parse_nmap_services\("),
        ),
        "existing": "Nmap XML and a structured CPE/service parser already exist.",
        "next": "Extend with Nikto JSON, normalized scanner records and database provenance; reuse the Nmap parser.",
    },
    "evidence": {
        "match": r"evidence|finding|beleg|citation",
        "signals": (
            ("src/source_verification.py", r"^def evidence_in_scan\("),
            ("src/assessment_quality.py", r"^def apply_review\("),
        ),
        "existing": "Scanner-quote verification and downgrading unsupported findings already exist.",
        "next": "Add durable evidence record IDs and link them in stored findings and HTML/PDF reports.",
    },
    "cve": {
        "match": r"cve|nvd|cpe|cvss|epss|kev|vulnerabilit",
        "signals": (
            ("src/cve_engine.py", r"^def discover\("),
            ("src/cve_priority.py", r"^def enrich_priority\("),
        ),
        "existing": "CPE-qualified NVD discovery plus CVSS, EPSS and KEV prioritization already exist.",
        "next": "Extend persistent/offline cache and structured candidate provenance rather than rebuilding CVE discovery.",
    },
    "injection": {
        "match": r"prompt.injection|prompt|untrusted|hardening|banner",
        "signals": (
            ("src/scan_input_budget.py", r"^def [a-z_]+\("),
            ("src/tools.py", r"^def run_tool_by_command\("),
        ),
        "existing": "Scanner-input budgets and restricted tool dispatch are already implemented.",
        "next": "Add stronger data-only prompt boundaries for target-controlled banners/headers and offline injection tests.",
    },
    "scan-diff": {
        "match": r"^(?:scan diff|scan comparison|comparison of scans)\b",
        "signals": (
            ("src/scan_trends.py", r"^def compare_sessions\("),
            ("src/export.py", r"^def add_saved_comparison\("),
        ),
        "complete": True,
        "existing": "Saved-session comparison with port/service/finding changes is already implemented.",
        "next": "Reuse Scan Diff & Trends; only open a follow-up issue for a specific missing capability.",
    },
    "workflow": {
        "match": r"workflow|cli|scan diff|scope|scan profiles?|export|sarif|queue|automation",
        "signals": (
            ("src/scan_trends.py", r"^def compare_sessions\("),
            ("src/export.py", r"^def export_html\("),
        ),
        "existing": "Scan Diff & Trends and HTML/PDF exports already exist.",
        "next": "Scope headless CLI, target allowlists, SARIF/redaction, profiles and queues as separate extensions.",
    },
    "hygiene": {
        "match": r"hygiene|installer|checksum|sha256|releases?|pinning|fixtures?|supply.chain",
        "signals": (
            ("install_scanners_windows.py", r"^def verify_nmap_sha256\("),
            (".github/workflows/release.yml", r"Get-FileHash.+SHA256"),
        ),
        "existing": "Official Nmap SHA256 verification and release ZIP checksums already exist.",
        "next": "Add independent integrity checks for WhatWeb/Nikto archives and expand parser fixtures.",
    },
}

STATES = {
    "implemented": "Implemented in reviewed code",
    "partially-implemented": "Partially implemented",
    "not-found-in-reviewed-code": "Not found in reviewed code",
    "needs-verification": "Needs verification",
}


def is_feature_request(issue: dict) -> bool:
    title = str(issue.get("title") or "")[:300]
    return bool(re.match(
        r"(?i)^\s*(?:\[feature(?: request)?\]|\[proposal\]|feature request\b|"
        r"feature\s*:|enhancement\b|proposal\s*:)", title
    ))


def _topics(issue: dict) -> list[tuple[str, str]]:
    """Use numbered Markdown sections, not just the issue title/first bullets."""
    body = str(issue.get("body") or "")[:11000]
    found = list(re.finditer(r"(?m)^##\s+([1-9][0-9]?)\.\s+(.+?)\s*$", body))
    if not found:
        return [(str(issue.get("title") or "Feature request")[:100], body[:2500])]
    items = []
    for i, match in enumerate(found[:MAX_TOPICS]):
        stop = found[i + 1].start() if i + 1 < len(found) else len(body)
        title = match.group(2).strip()[:100]
        items.append((title, body[match.end():stop][:2300]))
    return items


def _source_lines(root: Path) -> tuple[dict[str, list[str]], bool]:
    """Inspect production code/workflows, never .env, vendor bundles or tests."""
    sources: dict[str, list[str]] = {}
    globs = ("*.py", "*.bat", "src/**/*.py", "scripts/*.py",
             ".github/workflows/*.yml", ".github/workflows/*.yaml")
    paths = sorted({path for pattern in globs for path in root.glob(pattern)})
    if len(paths) > MAX_SOURCE_FILES:
        paths = paths[:MAX_SOURCE_FILES]
        complete = False
    else:
        complete = True
    root_real = root.resolve()
    for file in paths:
        if file.is_symlink() or not file.is_file():
            continue
        try:
            if not file.resolve().is_relative_to(root_real):
                continue
            if file.stat().st_size > MAX_SOURCE_SIZE:
                complete = False
                continue
            rel = file.relative_to(root).as_posix()
            sources[rel] = file.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            complete = False
    return sources, complete and bool(sources)


def _evidence(spec: dict, sources: dict[str, list[str]]) -> list[dict]:
    matches = []
    for path, pattern in spec["signals"]:
        if SOURCE_PATHS.get(path) in sources:
            path = SOURCE_PATHS[path]
        for index, line in enumerate(sources.get(path, []), 1):
            if re.search(pattern, line):
                matches.append({"file": path, "line": index})
                break
    return matches


def feature_review(root: Path, issue: dict) -> dict:
    """Classify every numbered proposal theme from checked-out, read-only code.

    Existing anchors are evidence that a capability exists, not proof that all
    proposed subfeatures are implemented. Missing anchors only mean the bounded
    reviewed code did not contain the known signature.
    """
    sources, complete = _source_lines(root)
    topics = []
    for number, (heading, body) in enumerate(_topics(issue), 1):
        key = next((name for name, spec in FEATURES.items()
                    if re.search(spec["match"], heading, re.I)), None)
        spec = FEATURES.get(key or "")
        anchors = _evidence(spec, sources) if spec else []
        if not spec:
            state = "needs-verification"
            existing = "No safe implementation mapping for this request."
            step = "Inspect the relevant implementation and decide scope with a maintainer."
        elif anchors:
            # Only tightly scoped capabilities with ALL implementation
            # signatures may be called implemented. Broader proposals remain
            # partial even when important foundations already exist.
            state = ("implemented" if spec.get("complete") and
                     len(anchors) == len(spec["signals"])
                     else "partially-implemented")
            existing, step = spec["existing"], spec["next"]
        elif complete:
            state = "not-found-in-reviewed-code"
            existing = "No matching implementation signature in reviewed production code."
            step = "Verify the missing functionality before designing new code."
        else:
            state = "needs-verification"
            existing = "Repository source inspection was incomplete."
            step = "Review available implementation files before planning changes."
        topics.append({
            "id": number, "title": heading, "state": state,
            "existing": existing, "next": step, "evidence": anchors[:2],
        })
    return {
        "verdict": "proposal",
        "summary": f"Reviewed {len(topics)} feature-request themes against local production source.",
        "reason": "Positive references show existing implementation; missing snippets "
                  "do not establish that a feature is absent repository-wide. "
                  "This is not a full implementation or runtime audit.",
        "verification": "source-inspection-only" if sources else "none",
        "feature_topics": topics, "evidence": [], "findings": [], "missing": [],
        "duplicate_issue": None, "impact": "",
        "next_step": "Extend existing modules first; split remaining improvements into scoped issues.",
    }
