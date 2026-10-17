"""Validated, structured local LLM reports; model JSON cannot invoke tools."""
from __future__ import annotations
import json

import requests
from jsonschema import validate, ValidationError
from penx_app.analysis.llm_client import complete_chat
from penx_app.analysis.assessment_quality import review_evidence

def string_field():
    return {"type": "string"}

def object_fields(fields):
    return {"type": "object", "properties": fields, "required": list(fields),
            "additionalProperties": False}

ANALYSIS_SCHEMA = object_fields({
    "vulnerabilities": {"type": "array", "items": object_fields({
        "vuln_name": string_field(),
        "severity": {"type": "string", "enum": ["critical","high","medium","low","info","unknown"]},
        "confidence": {"type": "string", "enum": ["confirmed","likely","possible"]},
        "port": string_field(), "service": string_field(),
        "description": string_field(), "evidence": string_field(),
        "fix": string_field(), "cve_ids": {"type": "array", "items": string_field()}
    })},
    "recommendations": {"type": "array", "items": object_fields({
        "vuln_name": string_field(), "description": string_field()
    })},
    "exploits": {"type": "array", "items": object_fields({
        "exploit_name": string_field(), "tool_used": string_field(),
        "payload": string_field(), "result": string_field(), "notes": string_field()
    })},
    "risk_level": {"type": "string", "enum": ["CRITICAL","HIGH","MEDIUM","LOW","UNKNOWN"]},
    "summary": string_field()
})

def parse_json_findings(text: str) -> dict:
    """Accept JSON (optionally fenced); enforce schema, bounds and enums."""
    raw = text.strip()
    fence = chr(96) * 3
    if raw.startswith(fence) and raw.endswith(fence):
        raw = raw[len(fence):-len(fence)].strip()
        if raw.lower().startswith("json"):
            raw = raw[4:].strip()
    data = json.loads(raw)
    validate(data, ANALYSIS_SCHEMA)
    if any(len(data[k]) > 100 for k in ("vulnerabilities", "recommendations", "exploits")):
        raise ValueError("Too many findings: maximum 100 entries per category.")
    for v in data["vulnerabilities"]:
        if not v["vuln_name"].strip() or len(v["evidence"]) > 3000:
            raise ValueError("Invalid finding name or evidence length.")
    return data

def request_structured_report(raw_scan: str, analysis: str, review: str, *,
                              url: str, models_url: str, model_name: str,
                              api_key: str = "", timeout: int = 600,
                              max_tokens: int = 8192, top_k: int = 10) -> dict:
    """Attempt schema-constrained output then JSON-object mode for older backends."""
    messages = [
        {"role": "system", "content": (
            "Format the assessment as a JSON object matching the supplied schema exactly. "
            "Never execute tools or add markdown. Quote scanner evidence literally; "
            "For vulnerabilities copy literal scanner quotations into EVIDENCE; "
            "do not add invented source labels, external search claims or paraphrases. "
            "If evidence is absent, use an empty string and confidence 'possible'. "
            "Recommendations have only name and description by design: do not "
            "invent an evidence key. Public version disclosures, normal Cloudflare "
            "ports, certificate names and SPF softfail alone are informational "
            "observations, not exploitable vulnerabilities. "
            "Do not invent CVEs or vulnerabilities."
        )},
        {"role": "user", "content": (
            "RAW SCAN (balanced excerpts from each scanner):\n" + review_evidence(raw_scan, per_source=5000) +
            "\nPRELIMINARY ANALYSIS:\n" + analysis[:14000] +
            "\nSELF REVIEW:\n" + review[:6000] +
            "\nRequired JSON schema:\n" + json.dumps(ANALYSIS_SCHEMA)
        )}
    ]
    formats: list[dict] = [
        {"type": "json_schema", "json_schema": {
            "name": "penx_findings", "strict": True, "schema": ANALYSIS_SCHEMA}},
        {"type": "json_object"}
    ]
    errors = []
    for fmt in formats:
        try:
            _, body = complete_chat(
                messages, url=url, models_url=models_url, model_name=model_name,
                api_key=api_key, timeout=timeout, max_tokens=max_tokens,
                top_k=top_k, temperature=0.1, response_format=fmt
            )
            return parse_json_findings(body)
        except requests.exceptions.HTTPError as exc:
            status = getattr(exc.response, "status_code", None)
            if status not in (400, 415, 422, 500, 501):
                raise
            errors.append("HTTP " + str(status))
        except (ValueError, ValidationError, json.JSONDecodeError) as exc:
            errors.append(str(exc)[:160])
    raise ValueError("Server returned no valid structured result: " + "; ".join(errors))
