"""Evidence-anchored second-pass review of an existing *unverified* AI draft.

A critic can request human re-evaluation, never confirmation, remediation,
new scanner execution or modification of the original finding. Both models'
prose is untrusted; exact saved excerpts are only quotation checks.
"""
from __future__ import annotations

from jsonschema import Draft202012Validator

from penx_app.domain.local_review import (
    MAX_RESPONSE_BYTES, MAX_REVIEW_FINDINGS, strict_json,
)

CRITIC_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "required": ["summary", "reviews"],
    "properties": {
        "summary": {"type": "string", "maxLength": 2000},
        "reviews": {
            "type": "array", "maxItems": MAX_REVIEW_FINDINGS,
            "items": {
                "type": "object", "additionalProperties": False,
                "required": ["fingerprint", "judgment", "rationale", "evidence_quote"],
                "properties": {
                    "fingerprint": {"type": "string"},
                    "judgment": {"enum": ["agrees", "disputes", "unresolved"]},
                    "rationale": {"type": "string", "minLength": 1, "maxLength": 1000},
                    "evidence_quote": {"type": "string", "maxLength": 1000},
                },
            },
        },
    },
}


def validate_critique(raw: str, sources: list[dict], primary: dict) -> dict:
    """A disagreement only carries a *literal* independently quoted excerpt.

    This verifies internal quote alignment and source identity, not truth,
    vulnerability applicability or semantic contradiction. The critic's
    'disputes' status must never be interpreted as proof of a false finding.
    """
    if not isinstance(raw, str) or len(raw.encode("utf-8")) > MAX_RESPONSE_BYTES:
        raise ValueError("Critic response exceeds 64 KiB")
    answer = strict_json(raw)
    Draft202012Validator(CRITIC_SCHEMA).validate(answer)

    source_by_id = {item["fingerprint"]: item for item in sources}
    primary_by_id = {item["fingerprint"]: item for item in primary["reviews"]}
    if len(source_by_id) != len(sources) or len(primary_by_id) != len(primary["reviews"]):
        raise ValueError("Ambiguous review source identities")
    used = set()
    for item in answer["reviews"]:
        key = item["fingerprint"]
        if key not in primary_by_id or key not in source_by_id or key in used:
            raise ValueError("Critic refers to an absent or repeated finding")
        used.add(key)
        quote = item["evidence_quote"]
        judgment = item["judgment"]
        if judgment == "unresolved":
            if quote:
                raise ValueError("Unresolved critic verdict must not imply supporting proof")
        else:
            if (len("".join(quote.split())) < 12
                    or quote not in source_by_id[key]["evidence"]):
                raise ValueError("Critic quote not anchored in original source excerpt")
            if (judgment == "disputes"
                    and (primary_by_id[key]["assessment"] == "insufficient_evidence"
                         or quote == primary_by_id[key]["evidence_quote"])):
                raise ValueError("Disagreement must cite a distinct source excerpt")
    return answer


def critic_summary(critique: dict, *, source_count: int) -> dict:
    """Derived advisory totals only; no model promotion of finding confidence."""
    if type(source_count) is not int or source_count < 0:
        raise ValueError("Invalid source count")
    results = critique["reviews"]
    return {
        "schema": "penx-review-critic-v1",
        "state": "second-pass-draft-unverified",
        "reviews": results,
        "summary": critique["summary"],
        "model_reported_disagreements": sum(
            row["judgment"] == "disputes" for row in results),
        "reviewed_findings": len(results),
        "unreviewed_findings": source_count - len(results),
        "vulnerability_verified": False,
        "contradiction_verified": False,
        "operator_review_required": True,
        "note": (
            "Model-reported agreement/disagreement is an advisory observation. "
            "A matching saved quote does not prove authenticity, actual "
            "contradiction, CVE applicability or exploitability."
        ),
    }
