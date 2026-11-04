"""PX-203 explainable *traceability*, not vulnerability confidence.

Only independently validated raw captures can establish original-source
provenance. Saved quotations, human/model confidence labels, and a stored
raw-artifact reference do not authorize such a claim in ordinary reports.
"""
from __future__ import annotations

from collections.abc import Mapping


def evidence_traceability(
    trace: Mapping[str, object] | None, *, quote_matched: bool,
) -> dict:
    """Bounded, deterministic ordinal traceability classification (0..2).

    Tier 0: no matching saved quote.
    Tier 1: matching quote somewhere in saved scan text.
    Tier 2: additionally one unambiguous section with typed COMPLETE outcome.

    Even tier 2 is NOT proof of raw capture integrity, independent
    corroboration, CVE applicability, remediation or exploitability.
    """
    source = trace or {}
    matched = quote_matched is True
    name = source.get("scanner")
    attributed = matched and isinstance(name, str) and bool(name)
    raw_status = source.get("scanner_status")
    status = raw_status if attributed and raw_status in (
        "COMPLETE", "PARTIAL", "FAILED") else "UNKNOWN"
    has_date = isinstance(source.get("recorded_at"), str) and bool(
        source["recorded_at"])
    stored_ref = bool(
        attributed and source.get("artifact_status")
        == "stored-reference-not-revalidated"
        and source.get("raw_artifact") is not None
    )
    usable_evidence = attributed and source.get("scanner_evidence") is True
    tier = (2 if usable_evidence and status == "COMPLETE"
            else (1 if matched else 0))
    label = (
        "typed-complete-section" if tier == 2
        else "saved-quote-only" if tier == 1
        else "unattributed"
    )
    return {
        "schema": "penx-evidence-traceability-v1",
        "traceability_tier": tier,
        "traceability_label": label,
        "dimensions": {
            "quote": "matched-saved-text" if matched else "not-established",
            "source_identity": (
                "unique-saved-section" if attributed else "unattributed"),
            "coverage": status,
            "typed_usable_evidence": (
                "recorded-usable" if usable_evidence else "not-established"),
            "freshness": (
                "recorded-date-only-not-age-verified" if has_date
                else "unknown"),
            "corroboration": "not-established",
            "raw_artifact": (
                "retained-reference-unverified" if stored_ref
                else "not-independently-verified"),
        },
        "original_source_revalidated": False,
        "independent_corroboration_verified": False,
        "vulnerability_verified": False,
        "exploitability_verified": False,
        "operator_review_required": True,
        "note": (
            "Traceability tier is ordinal, not a probability, risk score, "
            "CVE applicability check, or evidence that a vulnerability "
            "is exploitable. Original source bytes require separate "
            "independent revalidation."
        ),
    }
