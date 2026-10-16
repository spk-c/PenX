"""Pure review policy shared by reporting, risk and comparison."""
def active_vulnerabilities(data: dict) -> list[tuple]:
    """Current active findings, excluding hallucinations but retaining audit rows.

    Newer human corrections can re-verify an earlier hallucination. Correction
    IDs are monotonic even if timestamps share the same second.
    """
    latest: dict[int, str] = {}
    for record in sorted(data.get("corrections") or [], key=lambda row: row[0]):
        latest[record[2]] = str(record[3] or "").lower()
    return [row for row in data.get("vulns") or []
            if latest.get(row[0]) != "hallucination"]


