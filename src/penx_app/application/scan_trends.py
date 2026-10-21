"""Compare recorded PenX sessions without making network requests.

Missing observations are not evidence that a vulnerability was remediated.
The comparison is deterministic; optional AI narration must not change it.
"""
from __future__ import annotations

import ipaddress
import json
import re
from difflib import SequenceMatcher
from pathlib import Path
from penx_app.file_output import publish_unique
from defusedxml import ElementTree as ET
from defusedxml.common import DefusedXmlException

from penx_app.storage.db import get_all_history, get_session
from penx_app.domain.finding_policy import active_vulnerabilities
from penx_app.reporting.finding_trace import finding_trace, missing_finding_status, scanner_coverage


_PORT = re.compile(r"^\s*(\d{1,5})/(tcp|udp)\s+open\s+(\S+)(?:\s+([^\r\n]+))?", re.I | re.M)
_RISK = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def canonical_target(target: str) -> str:
    """Compare a user-entered target conservatively; avoid DNS resolution."""
    return str(target).strip().lower().rstrip("/")


def _needs_host_identity(data: dict) -> bool:
    target = str(data['history'][1]).strip()
    if '/' in target:
        try:
            ipaddress.ip_network(target, strict=False)
            return True
        except ValueError:
            pass
    summary = data.get('summary')
    raw = str(summary[2] or '') if summary else ''
    return (len(re.findall(r'<host(?:\s|>)', raw)) > 1 or
            len(re.findall(r'(?m)^Nmap scan report for ', raw)) > 1)


def _ports(data: dict, *, host_scoped: bool = False) -> tuple[dict, bool]:
    summary = data.get("summary")
    raw = str(summary[2] or "") if summary else ""
    # Only errors from Nmap invalidate Nmap coverage. A WhatWeb timeout in
    # another scanner section does not turn a completed Nmap scan incomplete.
    section = re.search(
        r"(?ms)^\[\s*NMAP OUTPUT\s*\]\s*$"
        r"([\s\S]*?)(?=^\[\s*[A-Za-z0-9_ /-]+ OUTPUT\s*\]\s*$|\Z)",
        raw
    )
    raw = section.group(1) if section else raw
    found: dict[str, dict] = {}
    # Prefer structured Nmap output, where service product/version are distinct.
    match = re.search(r"<nmaprun\b[\s\S]*?</nmaprun>", raw)
    parsed_xml = False
    xml_completed = False
    identity_complete = True
    if match and len(match.group()) <= 2_000_000:
        try:
            root = ET.fromstring(match.group())
            parsed_xml = root.tag == "nmaprun"
            finished = root.find("./runstats/finished")
            xml_completed = bool(
                parsed_xml and finished is not None
                and finished.get("exit") == "success"
            )
            seen_hosts = set()
            for host in root.findall('host'):
                address = ''
                if host_scoped:
                    # Never use host order or a MAC address as network identity.
                    addresses = set()
                    for entry in host.findall('address'):
                        if entry.get('addrtype') in {'ipv4', 'ipv6'}:
                            try:
                                addresses.add(str(ipaddress.ip_address(entry.get('addr', ''))))
                            except ValueError:
                                pass
                    if len(addresses) != 1:
                        identity_complete = False
                        continue
                    address = addresses.pop()
                    if address in seen_hosts:
                        identity_complete = False
                        continue
                    seen_hosts.add(address)
                for port in host.findall('./ports/port'):
                    state = port.find("state")
                    if state is None or state.get("state") != "open":
                        continue
                    proto, number = port.get("protocol", ""), port.get("portid", "")
                    # Nmap port IDs must be 1..65535. Canonicalizing the
                    # number also makes XML "080" and "80" the same port.
                    if (not number.isascii() or not number.isdecimal()
                            or len(number) > 5 or proto not in {"tcp", "udp"}):
                        continue
                    numeric_port = int(number)
                    if not 1 <= numeric_port <= 65535:
                        continue
                    service = port.find("service")
                    name = service.get("name", "unknown") if service is not None else "unknown"
                    version = " ".join(
                        service.get(part, "") for part in ("product", "version", "extrainfo")
                    ).strip() if service is not None else ""
                    key = f"{numeric_port}/{proto}"
                    if host_scoped:
                        key = f"{address} {key}"
                    found[key] = {"service": name, "version": version}
        except (ET.ParseError, DefusedXmlException, ValueError):
            pass
    if not parsed_xml:
        # Unattributed text port rows cannot safely compare multiple hosts.
        identity_complete = not host_scoped
        for match in _PORT.finditer(raw):
            port, proto, service, detail = match.groups()
            numeric_port = int(port)
            if not 1 <= numeric_port <= 65535:
                continue
            found[f"{numeric_port}/{proto.lower()}"] = {
                "service": service, "version": (detail or "").strip()
            }
    # XML must include successful runstats; text-only Nmap must show its
    # completion footer. Failed/timed-out tool wrappers override both signals.
    failed = bool(re.search(
        r"(?im)^\s*(?:\[EXIT CODE [1-9]\d*\]|\[!\] Timed out|"
        r"\[!\] Nmap is not installed|\[!\] Executable not found)",
        raw
    ))
    has_nmap = not failed and identity_complete and (
        xml_completed if parsed_xml else bool(re.search(r"Nmap done:", raw, re.I))
    )
    return found, has_nmap


def _findings(data: dict) -> dict:
    rows: dict[tuple[str, str, str], list[dict]] = {}
    for item in active_vulnerabilities(data):
        # Row shape: id, session, name, severity, confidence, port, service, description.
        key = (str(item[2] or "").strip().casefold(),
               str(item[5] or "").strip().casefold(),
               str(item[6] or "").strip().casefold())
        rows.setdefault(key, []).append({
            "name": str(item[2] or ""),
            "severity": str(item[3] or "unknown").lower(),
            "confidence": str(item[4] or "possible").lower(),
            "port": str(item[5] or ""),
            "service": str(item[6] or ""),
            "source": finding_trace(item, data),
            "description": str(item[7] or "")[:16000],
        })
    # Pair duplicate findings independently of storage insertion order.
    for group in rows.values():
        group.sort(key=lambda x: (x["severity"], x["confidence"], x["name"],
                                  x["port"], x["service"]))
    return rows


def _recommendation_topic(row: dict) -> str | None:
    """Conservative semantic grouping for known hardening subjects.

    Only *recommendations*, never actionable vulnerability records, can be
    paired by topic across renames. New issue types stay separate, and a
    reworded recommendation never implies a weakness was remediated.
    """
    if row.get("confidence") != "recommendation":
        return None
    name = str(row.get("name", "")).casefold()
    # Strong exact domain identity: distinguish separate API hosts.
    hostname = re.search(r"\b[a-z0-9_-]+(?:\.[a-z0-9_-]+){2,}\b", name)
    if hostname and (
        "api" in hostname.group() and
        any(term in name for term in ("scan", "investigate", "check", "review", "verify"))
    ):
        return "api-host:" + hostname.group()
    # Match reworded inventory recommendations by narrowly scoped product/control.
    if "elementor" in name and ("version" in name or "disclosure" in name):
        return "inventory:elementor-version"
    if "flyingpress" in name and ("version" in name or "disclosure" in name):
        return "inventory:flyingpress-version"
    if "content-security-policy" in name and "permissions-policy" not in name:
        return "headers:csp"
    if "cloudflare" in name and "8080" in name and "8443" in name:
        return "cloudflare:alternate-ports"
    if "dnssec" in name:
        return "dnssec"
    if "hsts" in name:
        return "hsts"
    if "dmarc" in name and "spf" in name:
        return "email-auth:spf+dmarc"
    if "dmarc" in name:
        return "email-auth:dmarc"
    if "spf" in name:
        return "email-auth:spf"
    return None


def _reworded_matches(fresh: list[dict], missing: list[dict]) -> tuple[list[dict], list[dict], list[dict], list[dict]]:
    """Find a best one-to-one pairing *after* exact finding matches.

    A topic match needs the same scoped recommendation category and a lexical
    similarity floor, so unrelated suggestions are never merged merely
    because they refer to the same generic security technology.
    """
    candidates = []
    for i, new in enumerate(fresh):
        topic = _recommendation_topic(new)
        if not topic:
            continue
        for j, old in enumerate(missing):
            if topic != _recommendation_topic(old):
                continue
            score = SequenceMatcher(None, old["name"].casefold(), new["name"].casefold()).ratio()
            if score >= 0.3:
                candidates.append((score, i, j, topic))
    pairs = []
    used_new, used_old = set(), set()
    for _score, i, j, topic in sorted(candidates, key=lambda item: -item[0]):
        if i in used_new or j in used_old:
            continue
        used_new.add(i)
        used_old.add(j)
        pairs.append({
            "from": missing[j]["name"], "to": fresh[i]["name"], "topic": topic
        })
    return (
        [r for i, r in enumerate(fresh) if i not in used_new],
        [r for i, r in enumerate(missing) if i not in used_old],
        [fresh[i] for i in sorted(used_new)],
        pairs,
    )


def _shodan_snapshots(data: dict) -> dict[str, dict]:
    """Parse *only* explicit InternetDB record blocks stored in the scan history."""
    summary = data.get("summary")
    raw = str(summary[2] or "") if summary else ""
    records = {}
    lines = raw.splitlines()
    for pos, line in enumerate(lines[:-1]):
        if line.strip() != "[SHODAN INTERNETDB RECORD]":
            continue
        payload = lines[pos + 1].strip()
        if len(payload) > 30_000:
            continue
        try:
            item = json.loads(payload)
        except (ValueError, TypeError):
            continue
        if not isinstance(item, dict) or item.get("source") != "Shodan InternetDB":
            continue
        ip = item.get("ip")
        if not isinstance(ip, str):
            continue
        # InternetDB integration only queries public IPv4 addresses. A
        # digit-and-dot regex accepts impossible or reserved IPs and could
        # turn malformed historical data into invented indexed-port changes.
        try:
            public_ip = ipaddress.IPv4Address(ip)
        except ValueError:
            continue
        if (not public_ip.is_global or public_ip.is_multicast
                or str(public_ip) != ip):
            continue
        ports = item.get("ports", [])
        cves = item.get("vulns", [])
        if not isinstance(ports, list) or not isinstance(cves, list):
            continue
        records[ip] = {
            "ports": {p for p in ports if type(p) is int and 1 <= p <= 65535},
            "vulns": {v for v in cves if isinstance(v, str)
                      and re.fullmatch(r"CVE-\d{4}-\d{4,7}", v, re.I)},
        }
    return records


def _shodan_diff(older: dict, newer: dict) -> dict:
    """Compare only matching IP snapshots from two complete InternetDB lookups."""
    previous, latest = _shodan_snapshots(older), _shodan_snapshots(newer)
    shared = sorted(previous.keys() & latest.keys())
    new_ports, missing_ports, new_cves, missing_cves = [], [], [], []
    for ip in shared:
        for port in sorted(latest[ip]["ports"] - previous[ip]["ports"]):
            new_ports.append({"ip": ip, "port": port})
        for port in sorted(previous[ip]["ports"] - latest[ip]["ports"]):
            missing_ports.append({"ip": ip, "port": port})
        for cve in sorted(latest[ip]["vulns"] - previous[ip]["vulns"]):
            new_cves.append({"ip": ip, "cve": cve})
        for cve in sorted(previous[ip]["vulns"] - latest[ip]["vulns"]):
            missing_cves.append({"ip": ip, "cve": cve})
    return {
        "comparable_ips": shared,
        "only_in_previous": sorted(previous.keys() - latest.keys()),
        "only_in_latest": sorted(latest.keys() - previous.keys()),
        "new_indexed_ports": new_ports,
        "no_longer_indexed_ports": missing_ports,
        "new_cve_candidates": new_cves,
        "no_longer_listed_cves": missing_cves,
        "note": ("Shodan InternetDB is a historical IP index with periodically refreshed "
                 "data. CVE matches may be unverified. No indexed entry proves "
                 "target exposure, exploitability or remediation."),
    }


def compare_sessions(older: dict, newer: dict) -> dict:
    """Compute observed changes; both sessions must exist and target must match."""
    if not older.get("history") or not newer.get("history"):
        raise ValueError("Both scan sessions must exist.")
    a, b = older["history"], newer["history"]
    if canonical_target(a[1]) != canonical_target(b[1]):
        raise ValueError("Select sessions for the same target.")
    # Use the same identity scheme on both sides, even if one scan lost a host.
    host_scoped = _needs_host_identity(older) or _needs_host_identity(newer)
    oldports, oldcomplete = _ports(older, host_scoped=host_scoped)
    newports, newcomplete = _ports(newer, host_scoped=host_scoped)
    oldfindings, newfindings = _findings(older), _findings(newer)
    fresh, missing, changed, still = [], [], [], []
    # Match identical severities first, independent of insertion order.
    # Only unmatched rows may represent a severity change.
    from collections import defaultdict, deque
    for key in sorted(oldfindings.keys() | newfindings.keys()):
        previous = oldfindings.get(key, [])
        current = newfindings.get(key, [])
        buckets: dict[str, deque[dict]] = defaultdict(deque)
        for row in previous:
            buckets[row["severity"]].append(row)
        unmatched_new = []
        for row in current:
            if buckets[row["severity"]]:
                buckets[row["severity"]].popleft()
                still.append(row)
            else:
                unmatched_new.append(row)
        unmatched_old: list[dict] = []
        for severity in sorted(buckets):
            unmatched_old.extend(buckets[severity])
        for old, new in zip(unmatched_old, unmatched_new):
            changed.append({"finding": new, "from": old["severity"],
                            "to": new["severity"]})
        missing.extend(unmatched_old[len(unmatched_new):])
        fresh.extend(unmatched_new[len(unmatched_old):])

    # Match renamed recommendations by specific subject only; do not conflate
    # generic CVEs, unrelated plugin findings, or different vulnerabilities.
    fresh, missing, reworded_present, reworded = _reworded_matches(fresh, missing)
    still.extend(reworded_present)

    # Legacy not_observed_findings retains all absent rows for API compatibility.
    # Only the new per-finding states distinguish incomplete scanner coverage.
    finding_states = []
    for finding in fresh:
        finding_states.append({"status": "new", "finding": finding})
    for finding in still:
        finding_states.append({"status": "still_present", "finding": finding})
    for change in changed:
        finding_states.append({
            "status": "severity_changed", "finding": change["finding"],
            "previous_severity": change["from"],
        })
    for finding in missing:
        status, reason = missing_finding_status(finding, newer)
        finding_states.append({"status": status, "finding": finding, "reason": reason})
    counts = {name: sum(state["status"] == name for state in finding_states)
              for name in ("new", "still_present", "severity_changed",
                           "not_observed", "not_checked", "scan_failed", "resolved")}

    return {
        "target": a[1], "from_session": a[0], "to_session": b[0],
        "from_date": str(a[2]), "to_date": str(b[2]),
        "new_findings": fresh,
        "not_observed_findings": missing,
        "finding_states": finding_states,
        "finding_state_counts": counts,
        "coverage_qualified_not_observed_findings": [
            state["finding"] for state in finding_states
            if state["status"] == "not_observed"
        ],
        "not_checked_findings": [
            state["finding"] for state in finding_states
            if state["status"] == "not_checked"
        ],
        "scan_failed_findings": [
            state["finding"] for state in finding_states
            if state["status"] == "scan_failed"
        ],
        "unreported_with_persistent_evidence": [
            state["finding"] for state in finding_states
            if state["status"] == "still_present" and state.get("reason")
        ],
        "resolved_findings": [],  # No automatic resolution from non-observation.
        "scanner_coverage": {
            "previous": scanner_coverage(older),
            "latest": scanner_coverage(newer),
        },
        "severity_changes": changed,
        "persistent_findings": still,
        "reworded_recommendations": reworded,
        "new_ports": {k: v for k, v in newports.items() if k not in oldports}
                     if oldcomplete and newcomplete else {},
        "missing_ports": {k: v for k, v in oldports.items() if k not in newports}
                         if oldcomplete and newcomplete else {},
        "service_changes": [
            {"port": k, "from": oldports[k], "to": newports[k]}
            for k in sorted(newports.keys() & oldports.keys())
            if newports[k] != oldports[k]
        ] if oldcomplete and newcomplete else [],
        "port_comparison_reliable": bool(oldcomplete and newcomplete),
        "shodan_internetdb": _shodan_diff(older, newer),
        "note": ("Not observed is not confirmed fixed. No finding is automatically "
                 "marked resolved. A negative recheck "
                 "with completed, comparable scanner coverage is still only "
                 "not_observed; missing tools, partial scans and unknown "
                 "provenance are kept separate as scan_failed/not_checked. "
                 "Port comparisons require complete Nmap scans of both sessions."),
    }


def report_text(diff: dict) -> str:
    lines = [
        f"SCAN DIFF | {diff['target']}",
        f"SL#{diff['from_session']} ({diff['from_date']}) -> "
        f"SL#{diff['to_session']} ({diff['to_date']})",
        f"New observations/advice: {len(diff['new_findings'])} | "
        f"Not repeated by model: {len(diff['not_observed_findings'])} | "
        f"Severity changed: {len(diff['severity_changes'])} | "
        f"Still present in model report: {len(diff['persistent_findings'])}",
    ]
    statuses = diff.get("finding_states")
    if statuses is not None:
        counts = diff.get("finding_state_counts", {})
        lines.append(
            "Finding states | " + " | ".join(
                f"{label}: {counts.get(key, 0)}"
                for key, label in (
                    ("new", "New"), ("still_present", "Still present"),
                    ("severity_changed", "Severity changed"),
                    ("not_observed", "Not observed"),
                    ("not_checked", "Not checked"),
                    ("scan_failed", "Scan failed"), ("resolved", "Resolved")
                )
            )
        )
        for entry in statuses:
            row = entry["finding"]
            label = entry["status"].upper().replace("_", " ")
            lines.append(f"  [{label}] {row['name']} | {row['severity']} | {row['port']}")
            if entry.get("reason"):
                lines.append("    Coverage: " + entry["reason"])
            trace = row.get("source") or {}
            source_name = trace.get("scanner") or "unattributed"
            version = trace.get("scanner_version") or "not recorded"
            lines.append(f"    Source: {source_name} | Version: {version} | "
                         f"Scan date: {trace.get('recorded_at') or 'unknown'} | "
                         f"Evidence: {trace.get('evidence_status') or 'review-required'}")
            if trace.get("evidence_ref"):
                lines.append("    Reference: " + trace["evidence_ref"])
            if trace.get("evidence"):
                lines.append("    Original scanner quote: " +
                             str(trace["evidence"])[:500].replace(chr(10), " "))
            if row.get("description"):
                lines.append("    Finding assessment: " +
                             str(row["description"])[:500].replace(chr(10), " "))
    else:
        for name, label in (
            ("new_findings", "NEW IN REPORT"),
            ("not_observed_findings", "NOT REPEATED"),
            ("persistent_findings", "PERSISTENT"),
        ):
            for f in diff[name]:
                lines.append(f"  [{label}] {f['name']} | {f['severity']} | {f['port']}")
    for item in diff["severity_changes"]:
        lines.append(f"  [SEVERITY] {item['finding']['name']}: {item['from']} -> {item['to']}")
    for pair in diff.get("reworded_recommendations", []):
        lines.append(f"  [REWORDED] {pair['from']} -> {pair['to']} "
                     "(same hardening topic; no fix inferred)")
    if diff["port_comparison_reliable"]:
        for name, label in (("new_ports", "OPENED"), ("missing_ports", "NOT OPEN")):
            for port, service in sorted(diff[name].items()):
                lines.append(f"  [{label}] {port}: {service['service']} {service['version']}")
        for change in diff["service_changes"]:
            lines.append(f"  [SERVICE] {change['port']}: {change['from']} -> {change['to']}")
    else:
        lines.append("  [PORTS] Inconclusive: both scans need complete Nmap results "
                     "and unambiguous host identities for multi-host targets.")
    shodan = diff.get("shodan_internetdb", {})
    if shodan.get("comparable_ips"):
        lines.append("[SHODAN INTERNETDB HISTORICAL INDEX CHANGES]")
        for ip in shodan["comparable_ips"]:
            lines.append(f"  Indexed IP {ip}: external observations, not live probes")
        for key, label, field in (
            ("new_indexed_ports", "NEWLY INDEXED PORT", "port"),
            ("no_longer_indexed_ports", "PORT NO LONGER INDEXED", "port"),
            ("new_cve_candidates", "NEW CVE CANDIDATE", "cve"),
            ("no_longer_listed_cves", "CVE NO LONGER LISTED", "cve"),
        ):
            for record in shodan[key]:
                lines.append(f"  [{label}] {record['ip']}: {record[field]}")
        lines.append(shodan["note"])
    elif shodan.get("only_in_previous") or shodan.get("only_in_latest"):
        lines.append("[SHODAN INTERNETDB] Different indexed IPs or missing "
                     "snapshots; do not infer exposure changes.")
    lines.append(diff["note"])
    return "\n".join(lines)


def matching_history(target: str) -> list[tuple]:
    return [row for row in reversed(get_all_history())
            if canonical_target(row[1]) == canonical_target(target)]


def compare_ids(older_id: int, newer_id: int) -> dict:
    return compare_sessions(get_session(older_id), get_session(newer_id))


def history_trend(target: str) -> list[dict]:
    """Chronological trend of saved risk levels and finding counts."""
    result = []
    for row in matching_history(target):
        record = get_session(row[0])
        risk = (record.get("summary") or [None] * 5)[4] or "UNKNOWN"
        result.append({
            "session": row[0], "date": str(row[2]),
            "risk": risk, "risk_rank": _RISK.get(str(risk).upper(), 0),
            "findings": len(active_vulnerabilities(record)),
        })
    return result


def save_diff(diff: dict, directory: str | Path) -> Path:
    destination = Path(directory)
    destination.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^A-Za-z0-9_-]", "_", diff["target"])[:48] or "target"
    name = f"diff_{safe}_{diff['from_session']}_{diff['to_session']}.json"
    return publish_unique(destination, name.removesuffix(".json"), ".json",
                          json.dumps(diff, indent=2, ensure_ascii=False) + "\n")


def export_diff_reports(diff: dict, directory: str | Path) -> dict[str, Path]:
    """Write JSON, self-contained HTML and PDF from the same verified diff."""
    from html import escape
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer

    json_file = save_diff(diff, directory)
    base = json_file.with_suffix("")
    plain = report_text(diff)
    html_file = base.with_suffix(".html")
    html_file.write_text(
        '<!doctype html><html lang="en"><meta charset="utf-8">'
        '<title>PenX Scan Diff</title><style>body{background:#151823;color:#eee;'
        'font:15px/1.5 system-ui;padding:30px}pre{white-space:pre-wrap;'
        'overflow-wrap:anywhere}</style><h1>PenX Scan Diff</h1><pre>' +
        escape(plain, quote=True) + "</pre></html>", encoding="utf-8")
    pdf_file = base.with_suffix(".pdf")
    doc = SimpleDocTemplate(str(pdf_file), pagesize=A4,
                            leftMargin=40, rightMargin=40)
    style = ParagraphStyle("DiffLines", parent=getSampleStyleSheet()["BodyText"],
                           fontSize=8, leading=11, wordWrap="CJK")
    story = [Paragraph("PenX Scan Diff", getSampleStyleSheet()["Heading1"]),
             Spacer(1, 12)]
    for line in plain.splitlines():
        story.append(Paragraph(escape(line, quote=True).replace(" ", "&nbsp;"),
                               style))
    doc.build(story)
    return {"json": json_file, "html": html_file, "pdf": pdf_file}
