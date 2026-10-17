"""Evidence-aware review gates for local-LLM security assessments.

Scanner evidence is retained for the full report, but balanced snippets are
selected for model review so verbose Nmap/XML cannot hide other scanner data.
An AI review verdict is advisory; deterministic evidence and finding-type
checks are applied before persisting any vulnerability.
"""
from __future__ import annotations

import re
from penx_app.analysis.scan_input_budget import bound_scan_text
from penx_app.intelligence.source_verification import evidence_in_scan


HEADINGS = re.compile(r"(?m)^\[[ \t]*([A-Za-z0-9_ /(),.-]+?)[ \t]+OUTPUT[ \t]*\]\r?$")
POSITIVE_WEAKNESS = re.compile(
    r"\b(cve-\d{4}-\d+|vulnerab\w*|unauthenticated|authorization bypass|"
    r"exploitable|unpatched|weak cipher|misconfigur\w*|open redirect|"
    r"credential exposure|sql injection|cross.site scripting)\b", re.I
)
OBSERVATIONS = (
    re.compile(r"\b(?:alternate|additional|exposed|open)\b.*\bports?\b", re.I),
    re.compile(r"\bports?\b.*\b(?:alternate|additional|open|exposed)\b", re.I),
    re.compile(r"\bcertificate\b.*\b(?:san|subdomain|naming)\b", re.I),
    re.compile(r"\b(?:san|subdomain)\b.*\b(?:certificate|naming)\b", re.I),
    re.compile(r"\b(?:public\s+)?(?:plugin\s+)?version disclosure\b", re.I),
    re.compile(r"\bspf softfail\b", re.I),
)


MAX_REVIEW_SECTIONS = 48
MAX_REVIEW_CHARS = 60_000


def review_evidence(raw_scan: str, *, per_source: int = 12000) -> str:
    """Balanced review evidence with a hard combined model-context budget."""
    per_source = max(256, min(int(per_source), 12000))
    boundaries = [m for m in HEADINGS.finditer(raw_scan)
                  if m.group(1).strip().upper() != "PARTIAL"]
    if not boundaries:
        return bound_scan_text(_clip(raw_scan, max(per_source, 30000)),
                               limit=MAX_REVIEW_CHARS)
    section_indices = list(range(len(boundaries)))
    sections = []
    if len(boundaries) > MAX_REVIEW_SECTIONS:
        head = MAX_REVIEW_SECTIONS // 2
        tail = MAX_REVIEW_SECTIONS - head
        section_indices = list(range(head)) + list(range(len(boundaries) - tail,
                                                         len(boundaries)))
        omitted = len(boundaries) - MAX_REVIEW_SECTIONS
        sections.append(
            f"[REVIEW EVIDENCE SAMPLED: {omitted} scanner section(s) omitted; "
            "original raw scan retained. Omitted data is not a negative finding.]"
        )
    for i in section_indices:
        match = boundaries[i]
        end = boundaries[i + 1].start() if i + 1 < len(boundaries) else len(raw_scan)
        segment = raw_scan[match.end():end].strip()
        # A verbose Nmap XML appendix should not eclipse port/service evidence.
        if match.group(1).strip().upper() == "NMAP":
            segment = segment.split("[NMAP STRUCTURED XML]", 1)[0]
        sections.append(f"[{match.group(1).strip()} OUTPUT]\n{_clip(segment, per_source)}")
    # Each section can be 12 kB; the total must still fit the next model
    # request. Use the existing balanced selector to preserve early and late
    # high-signal lines while marking omissions clearly.
    return bound_scan_text("\n\n".join(sections), limit=MAX_REVIEW_CHARS)


def _clip(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    head = int(limit * .72)
    return value[:head] + "\n[... evidence omitted for review; original scan retained ...]\n" + value[-(limit - head):]


def reviewer_report(vulnerabilities: list[dict], recommendations: list[dict]) -> str:
    """Give review exact final finding names, not speculative earlier tool rounds."""
    parts = []
    for kind, items in (("VULNERABILITIES", vulnerabilities), ("RECOMMENDATIONS", recommendations)):
        parts.append(f"FINAL {kind}:")
        for item in items:
            parts.append(f"REVIEW THIS EXACT NAME: {item.get('vuln_name', '')}")
            parts.append(f"SEVERITY: {item.get('severity', 'info')}")
            if kind == "VULNERABILITIES":
                parts.append(f"EVIDENCE: {item.get('evidence', '')}")
            else:
                # Recommendations have no EVIDENCE property in ANALYSIS_SCHEMA.
                # Review whether their factual assertions are grounded, but
                # missing a dedicated evidence field is NOT a defect.
                parts.append("RECOMMENDATION: No dedicated EVIDENCE field in the schema.")
            parts.append(f"DESCRIPTION: {item.get('description', '')[:1200]}")
    return "\n".join(parts)


def _name(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", value.casefold()).strip()


def _flag_for(record: dict, flags: list[dict]) -> dict | None:
    key = _name(str(record.get("vuln_name", "")))
    for flag in flags:
        if key and key == _name(str(flag.get("vuln_name", ""))):
            return flag
    return None


def _mark(record: dict, flag: dict | None) -> None:
    if flag:
        record["_review_flag"] = flag["verdict"]
        for source, dest in (
            ("evidence", "_review_evidence"),
            ("issue", "_review_issue"),
            ("corrected", "_review_corrected"),
        ):
            record[dest] = flag.get(source, "")


def _observation(record: dict) -> bool:
    label = str(record.get("vuln_name", ""))
    return any(pattern.search(label) for pattern in OBSERVATIONS) and not POSITIVE_WEAKNESS.search(label)


def _correct_ssh_cve_identity(item: dict) -> None:
    """Fix a known CVE/name mix-up even when the model reviewer misses it.

    CVE-2023-48795 is Terrapin, not regreSSHion (CVE-2024-6387).
    A version banner cannot establish Terrapin applicability: SSH algorithms
    and vendor patches matter. Preserve the original wording for audit.
    """
    body = str(item.get("description", ""))
    name = str(item.get("vuln_name", ""))
    pair = re.compile(r"(?i)\bregresshion\s*(?:\(?\s*)?CVE-2023-48795\b[^\n.!?]*(?:\.\d+)?[.!?]?")
    reverse = re.compile(r"(?i)\bCVE-2023-48795\s*\(?\s*regresshion\b[^\n.!?]*(?:\.\d+)?[.!?]?")
    correction = ("Terrapin (CVE-2023-48795) concerns SSH transport integrity; "
                  "applicability depends on negotiated algorithms and vendor patches, "
                  "not the OpenSSH version banner alone. "
                  "regreSSHion is the distinct CVE-2024-6387.")
    fixed = reverse.sub(correction, pair.sub(correction, body))
    if fixed == body and not pair.search(name) and not reverse.search(name):
        return
    item["_review_original_description"] = body
    item["_review_flag"] = "corrected"
    item["_review_issue"] = "CVE identity mismatch: Terrapin is CVE-2023-48795; regreSSHion is CVE-2024-6387."
    item["_review_corrected"] = fixed
    item["description"] = fixed
    item["vuln_name"] = reverse.sub("Terrapin CVE-2023-48795",
                                     pair.sub("Terrapin CVE-2023-48795", name))


def _nmap_smtp_587_auth_evidence(raw_scan: str) -> bool:
    """Find 587/tcp evidence in its *own* Nmap service block, not port 25."""
    section = raw_scan.split("[NMAP STRUCTURED XML]", 1)[0]
    match = re.search(r"(?ms)^\s*587/tcp\s+open\s+smtp\b(.*?)(?=^\s*\d+/tcp\s+|^Service Info:|^Nmap done:|\Z)", section)
    if not match:
        return False
    return bool(re.search(r"\bsmtp-commands:.*?\bAUTH\s+PLAIN\s+LOGIN\b.*?\bSTARTTLS\b",
                          match.group(1), re.I | re.S))


def _smtp_auth_claim_supported(item: dict, raw_scan: str) -> None:
    """Correct the review's missing-port-587 claim without claiming TLS bypass."""
    title = str(item.get("vuln_name", ""))
    issue = str(item.get("_review_issue", ""))
    if not (re.search(r"SMTP.*AUTH|AUTH.*SMTP", title, re.I)
            and re.search(r"587", issue)
            and re.search(r"not (?:clearly |separately )?(?:captured|shown|show|available|present|recorded)|no separate|does not (?:clearly )?show", issue, re.I)
            and _nmap_smtp_587_auth_evidence(raw_scan)):
        return
    previous = str(item.get("description", ""))
    fact = ("The Nmap 587/tcp service block separately advertises AUTH PLAIN LOGIN "
            "and STARTTLS (as does the 25/tcp block). Advertisement does not "
            "demonstrate that unencrypted credentials are actually accepted.")
    item["_review_original_description"] = previous
    item["_review_flag"] = "corrected"
    item["_review_corrected"] = fact
    item["_review_issue"] = ("Review evidence omission corrected: Nmap explicitly recorded "
                             "the 587/tcp smtp-commands block. Authentication without TLS "
                             "has not been verified.")
    item["description"] = fact


_SEVERITIES = ("critical", "high", "medium", "low", "info")


def _apply_review_severity(item: dict, flag: dict | None) -> None:
    """Persist an explicit self-review downgrade, not just the audit note."""
    if not flag or flag.get("verdict") not in ("downgraded", "corrected"):
        return
    correction = str(flag.get("corrected") or "")
    # Only accept a stated severity change, not incidental mentions of HIGH.
    match = re.search(r"(?i)\bseverity\s*(?::|=|should be|to|is)?\s*"
                      r"(critical|high|medium|low|info)\b", correction)
    if not match:
        return
    updated = match.group(1).lower()
    original = str(item.get("severity", "")).lower()
    if original == updated or updated not in _SEVERITIES:
        return
    # A reviewer should not silently upgrade the severity.
    if original in _SEVERITIES and _SEVERITIES.index(updated) < _SEVERITIES.index(original):
        return
    item["_review_original_severity"] = original
    item["severity"] = updated
    item["_review_flag"] = "downgraded" if flag.get("verdict") == "downgraded" else "corrected"
    if not item.get("_review_original_description"):
        item["_review_original_description"] = item.get("description", "")


def _ssh_server_cve_review(item: dict, raw_scan: str) -> bool:
    """Reclassify SSH server CVE claims unsupported by the observed 7.4 banner.

    CVE-2024-6387 (regreSSHion) is a regression in upstream 8.5p1-9.7p1;
    4.4p1 through 8.4p1, including 7.4, is not affected by that regression.
    CVE-2023-38408 concerns ssh-agent / forwarded PKCS#11 loading, which cannot
    be inferred from an SSH server banner on TCP/22.
    No OS/distro patch state is inferred. The original model claim remains in
    the review correction and AI transcript for audit.
    """
    claim = " ".join(str(item.get(key) or "") for key in ("vuln_name", "description", "cve_ids"))
    if not re.search(r"(?i)\bCVE-2024-6387\b|\bCVE-2023-38408\b", claim):
        return False
    service = str(item.get("service") or "").lower()
    port = str(item.get("port") or "")
    if not (port == "22" or "ssh" in service
            or "openssh" in str(item.get("vuln_name", "")).lower()):
        return False
    banner = re.search(r"(?im)^\s*22/tcp\s+open\s+ssh\s+OpenSSH\s+(\d+)\.(\d+)", raw_scan)
    if not banner:
        return False
    version = (int(banner.group(1)), int(banner.group(2)))
    cves = set(re.findall(r"(?i)\bCVE-\d{4}-\d+\b", claim))
    cves = {value.upper() for value in cves}
    wrong_regression = "CVE-2024-6387" in cves and (4, 4) <= version < (8, 5)
    agent_only = "CVE-2023-38408" in cves
    if not (wrong_regression or agent_only):
        return False
    # Only entirely relabel an SSH-vulnerability finding if all referenced
    # CVEs in it were refuted by the available server-only evidence.
    unsupported = set()
    if wrong_regression:
        unsupported.add("CVE-2024-6387")
    if agent_only:
        unsupported.add("CVE-2023-38408")
    if cves - unsupported:
        return False
    previous = str(item.get("description", ""))
    old_sev = str(item.get("severity") or "")
    item["_review_original_description"] = previous
    item["_review_original_name"] = str(item.get("vuln_name") or "")
    item["_review_original_severity"] = old_sev
    item["_review_flag"] = "reclassified"
    item["_review_issue"] = ("CVE component/range gate: the observed OpenSSH "
                             "server banner does not support these CVE claims.")
    item["_review_corrected"] = (
        f"OpenSSH {banner.group(1)}.{banner.group(2)} was observed on 22/tcp. "
        + ("This upstream version is outside the regreSSHion CVE-2024-6387 "
           "regression range (8.5p1-9.7p1). " if wrong_regression else "")
        + ("CVE-2023-38408 targets ssh-agent/PKCS#11 forwarding, not the "
           "server merely listening on port 22. " if agent_only else "")
        + "Verify the exact vendor package, patch level and relevant client "
          "configuration independently; no exploitable SSH CVE was demonstrated.")
    item["vuln_name"] = "Verify OpenSSH package and SSH agent configuration"
    item["description"] = item["_review_corrected"]
    item["severity"] = "info"
    item["confidence"] = "recommendation"
    item["_reclassified"] = True
    item["fix"] = ""
    return True


def apply_review(vulnerabilities: list[dict], recommendations: list[dict],
                 raw_scan: str, flags: list[dict]) -> tuple[list[dict], list[dict], list[dict]]:
    """Keep only evidence-supported vulnerability claims and review-valid recommendations.

    Missing citations, informational observations and reviewer reclassifications
    become explicit recommendations; a hallucination verdict rejects its finding.
    Rejected proposals remain available in the full assessment/review audit text.
    """
    approved = []
    advice = []
    rejected = []
    for record in vulnerabilities:
        item = dict(record)
        flag = _flag_for(item, flags)
        _mark(item, flag)
        _correct_ssh_cve_identity(item)
        verdict = (flag or {}).get("verdict", "")
        if verdict == "hallucination":
            rejected.append(item)
            continue
        _apply_review_severity(item, flag)
        if _ssh_server_cve_review(item, raw_scan):
            advice.append(item)
            continue

        evidence = str(item.get("evidence", ""))
        # A reviewer correction becomes the effective wording. Keep the original
        # separately for the immutable corrections/audit record.
        corrected = str(item.get("_review_corrected") or "").strip()
        if verdict in {"corrected", "downgraded"} and corrected:
            if not item.get("_review_original_description"):
                item["_review_original_description"] = item.get("description", "")
            item["description"] = corrected
        # A fingerprint and an external advisory are not proof that an unknown
        # installed version belongs to the vulnerable version range.
        version_unknown = (
            str(item.get("confidence", "")).lower() == "possible"
            and re.search(r"version (?:is )?(?:unknown|not disclosed)|exact version .*not",
                          str(item.get("description", "")) + " " +
                          str(item.get("_review_issue", "")), re.I)
            and re.search(r"version|plugin|wordpress|flyingpress|elementor",
                          str(item.get("vuln_name", "")) + " " +
                          str(item.get("description", "")), re.I)
        )
        supported = evidence_in_scan(evidence, raw_scan)
        informational = item.get("severity", "").lower() in {"info", "unknown"}
        observational = _observation(item)
        reclassify = verdict in {"reclassified"} or version_unknown
        if informational or observational or reclassify or not supported:
            why = ("Informational observation, not a verified vulnerability."
                   if informational or observational or reclassify
                   else "Unverified scanner evidence; verify before treating as a vulnerability.")
            item["description"] = (why + "\n" + str(item.get("description", ""))).strip()
            item["severity"] = "info"
            item["confidence"] = "recommendation"
            item["_reclassified"] = True
            advice.append(item)
        else:
            approved.append(item)
    for record in recommendations:
        item = dict(record)
        flag = _flag_for(item, flags)
        _mark(item, flag)
        _correct_ssh_cve_identity(item)
        _smtp_auth_claim_supported(item, raw_scan)
        if (flag or {}).get("verdict") == "hallucination":
            rejected.append(item)
            continue
        # The model may still issue a spurious correction for a recommendation
        # simply because its schema has no EVIDENCE field. Do not persist those
        # as meaningful correction events. Other review verdicts are retained.
        issue = str(item.get("_review_issue", "")).casefold()
        if item.get("_review_flag") == "corrected" and (
            "evidence field was empty" in issue or
            "evidence field is empty" in issue or
            "recommendation evidence field" in issue
        ) and not any(word in issue for word in (
            "not supported", "unsupported", "fabricated", "unverified",
            "incorrect", "contradict", "not actionable", "hallucinat",
        )):
            for key in ("_review_flag", "_review_evidence", "_review_issue", "_review_corrected"):
                item.pop(key, None)
        if item.get("_review_flag") == "corrected" and item.get("_review_corrected") and not item.get("_review_original_description"):
            item["_review_original_description"] = item.get("description", "")
            item["description"] = str(item["_review_corrected"]).strip()
        advice.append(item)
    # Normalize product taxonomy in generated recommendation prose only.
    # FlyingPress is a WordPress caching/performance plugin, not a theme.
    for item in advice:
        title = str(item.get("vuln_name", ""))
        body = str(item.get("description", ""))
        if "flyingpress" in (title + body).lower():
            item["vuln_name"] = re.sub(r"(?i)(FlyingPress) theme", r"\1 plugin", title)
            item["description"] = re.sub(r"(?i)(FlyingPress) theme", r"\1 plugin", body)
    # Merge matching version-verification advice even when the model varies
    # the wording. Preserve all distinct subjects and security controls.
    unique = []
    keys = set()
    for item in advice:
        title = str(item.get("vuln_name", "")).casefold()
        body = str(item.get("description", "")).casefold()
        topic = next((product for product in ("flyingpress", "elementor", "wordpress")
                      if product in title and ("version" in title or "version" in body)),
                     None)
        if topic == "wordpress" and ("plugin" in title or "theme" in title):
            topic = None
        dedup_key = ("verify-version", topic) if topic else ("exact", re.sub(r"\W+", " ", title).strip())
        if dedup_key in keys:
            continue
        keys.add(dedup_key)
        unique.append(item)
    return approved, unique, rejected
