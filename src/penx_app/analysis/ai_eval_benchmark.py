"""PX-403: deterministic offline scoring of labelled, synthetic AI findings.

No model, network, scanner, database or user file is accessed by this module.
A scored quote must exactly equal a rubric anchor in its own case. These
numbers measure only the supplied fixture/prediction files, not field accuracy.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from typing import Any

CORPUS_SCHEMA = "penx-ai-eval-corpus-v1"
PREDICTIONS_SCHEMA = "penx-ai-eval-predictions-v1"
REPORT_SCHEMA = "penx-ai-eval-report-v1"
MAX_INPUT_BYTES = 1024 * 1024
MAX_CASES = 100
MAX_ITEMS_PER_CASE = 64
_ID = re.compile(r"[a-z][a-z0-9_-]{1,63}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_FAILURE_STATUSES = frozenset({"refusal", "timeout", "invalid_json"})


def _object_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate evaluation JSON field")
        result[key] = value
    return result


def read_bounded_json(path: str | Path) -> tuple[dict[str, Any], str]:
    """Read one local JSON input with strict duplicate and size checks."""
    file = Path(path)
    if file.is_symlink() or not file.is_file():
        raise ValueError("Expected an ordinary evaluation JSON file")
    if file.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError("Evaluation input exceeds 1 MiB")
    with file.open("rb") as source:
        raw = source.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError("Evaluation input exceeds 1 MiB")
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=_object_no_duplicates)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise ValueError("Invalid evaluation JSON") from exc
    if not isinstance(data, dict):
        raise ValueError("Evaluation JSON must be an object")
    return data, hashlib.sha256(raw).hexdigest()


def _keys(value: object, required: set[str], context: str) -> dict:
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError(f"Invalid {context} shape")
    return value


def _identifier(value: object, context: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError(f"Invalid {context} identifier")
    return value


def _document(value: object, schema: str) -> tuple[str, list]:
    data = _keys(value, {"schema", "prompt_sha256", "cases"}, "evaluation document")
    if data["schema"] != schema:
        raise ValueError("Unsupported evaluation document version")
    prompt_hash = data["prompt_sha256"]
    if not isinstance(prompt_hash, str) or not _SHA256.fullmatch(prompt_hash):
        raise ValueError("Prompt SHA-256 must be pinned")
    cases = data["cases"]
    if not isinstance(cases, list) or not 1 <= len(cases) <= MAX_CASES:
        raise ValueError("Invalid number of evaluation cases")
    return prompt_hash, cases


def _rubric(value: object) -> tuple[dict[str, dict], dict[str, str]]:
    _, cases = _document(value, CORPUS_SCHEMA)
    expectations: dict[str, dict] = {}
    evidence_hashes: dict[str, str] = {}
    for item in cases:
        case = _keys(item, {"id", "evidence", "expected"}, "corpus case")
        key = _identifier(case["id"], "case")
        if key in expectations:
            raise ValueError("Duplicate corpus case")
        evidence = case["evidence"]
        if not isinstance(evidence, str) or not 0 < len(evidence) <= 20000:
            raise ValueError("Invalid bounded synthetic case evidence")
        rows = case["expected"]
        if not isinstance(rows, list) or len(rows) > MAX_ITEMS_PER_CASE:
            raise ValueError("Too many rubric claims")
        expected: dict[str, str | None] = {}
        for row in rows:
            item = _keys(row, {"id", "supported", "quote"}, "rubric claim")
            finding_id = _identifier(item["id"], "rubric finding")
            if finding_id in expected or type(item["supported"]) is not bool:
                raise ValueError("Duplicate or invalid rubric finding")
            quote = item["quote"]
            if item["supported"]:
                if (not isinstance(quote, str) or not quote
                        or len(quote) > 2000 or quote not in evidence):
                    raise ValueError("Supported rubric claim lacks its exact source quote")
                expected[finding_id] = quote
            else:
                if quote is not None:
                    raise ValueError("Unsupported rubric claim may not have an anchor")
                expected[finding_id] = None
        expectations[key] = expected
        evidence_hashes[key] = hashlib.sha256(evidence.encode("utf-8")).hexdigest()
    return expectations, evidence_hashes


def score_predictions(corpus: dict, predictions: dict) -> dict:
    """Evaluate bounded predictions; return *counts only*, never source text.

    This is deliberately an exact-anchor rubric, not proof of semantic
    vulnerability applicability. Unknown identifiers and wrong quotes count
    as false positives, while missing supported anchors count as false
    negatives. An explicitly refused/timed-out/invalid case has no claims.
    """
    corpus_prompt, _ = _document(corpus, CORPUS_SCHEMA)
    prediction_prompt, entries = _document(predictions, PREDICTIONS_SCHEMA)
    if corpus_prompt != prediction_prompt:
        raise ValueError("Prompt versions do not match")
    rubric, _ = _rubric(corpus)
    supplied: dict[str, dict[str, str | None]] = {}
    failed = {status: 0 for status in sorted(_FAILURE_STATUSES)}
    for row in entries:
        item = _keys(row, {"id", "status", "findings"}, "prediction case")
        case_id = _identifier(item["id"], "prediction case")
        if case_id in supplied:
            raise ValueError("Duplicate prediction case")
        status, claims = item["status"], item["findings"]
        if status not in _FAILURE_STATUSES | {"complete"}:
            raise ValueError("Invalid prediction status")
        if not isinstance(claims, list) or len(claims) > MAX_ITEMS_PER_CASE:
            raise ValueError("Unbounded prediction findings")
        if status in _FAILURE_STATUSES:
            if claims:
                raise ValueError("Incomplete predictions cannot claim findings")
            failed[status] += 1
        parsed: dict[str, str] = {}
        for claim in claims:
            finding = _keys(claim, {"id", "quote"}, "prediction finding")
            fid = _identifier(finding["id"], "prediction finding")
            quote = finding["quote"]
            if fid in parsed or not isinstance(quote, str) or len(quote) > 2000:
                raise ValueError("Duplicate or malformed prediction finding")
            parsed[fid] = quote
        supplied[case_id] = parsed
    if set(supplied) != set(rubric):
        raise ValueError("Prediction cases must match the rubric exactly")

    tp = fp = fn = unsupported_predictions = 0
    for case_id, expected in rubric.items():
        predicted = supplied[case_id]
        for fid, quote in predicted.items():
            required = expected.get(fid)
            if required is not None and quote == required:
                tp += 1
            else:
                fp += 1
                if required is None:
                    unsupported_predictions += 1
        for fid, required in expected.items():
            if required is not None and predicted.get(fid) != required:
                fn += 1
    return {
        "schema": REPORT_SCHEMA,
        "mode": "offline-labelled-fixture",
        "real_model_executed": False,
        "real_target_scanned": False,
        "case_count": len(rubric),
        "successful_prediction_cases": len(rubric) - sum(failed.values()),
        "failure_cases": failed,
        "true_positive_anchors": tp,
        "false_positive_or_unanchored_claims": fp,
        "unsupported_or_unknown_claims": unsupported_predictions,
        "missing_supported_anchors": fn,
        "precision": round(tp / (tp + fp), 4) if tp + fp else None,
        "recall": round(tp / (tp + fn), 4) if tp + fn else None,
        "interpretation": "Synthetic exact-quote rubric only; not a measured model accuracy, live security verdict or vulnerability proof.",
    }
