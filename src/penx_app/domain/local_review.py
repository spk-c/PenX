"""Evidence-constrained local-AI drafts; never an executable action contract."""
from __future__ import annotations

import json
import re

MAX_REVIEW_FINDINGS = 20
MAX_PROMPT_CHARS = 24_000
MAX_RESPONSE_BYTES = 65_536

REVIEW_SCHEMA = {
    'type': 'object', 'additionalProperties': False,
    'required': ['summary', 'reviews'],
    'properties': {
        'summary': {'type': 'string', 'maxLength': 2000},
        'reviews': {'type': 'array', 'maxItems': MAX_REVIEW_FINDINGS, 'items': {
            'type': 'object', 'additionalProperties': False,
            'required': ['fingerprint', 'assessment', 'rationale', 'evidence_quote', 'suggested_scanner_key'],
            'properties': {
                'fingerprint': {'type': 'string'},
                'assessment': {'enum': ['needs_review', 'insufficient_evidence', 'informational']},
                'rationale': {'type': 'string', 'minLength': 1, 'maxLength': 1000},
                'evidence_quote': {'type': 'string', 'maxLength': 1000},
                'suggested_scanner_key': {'type': ['string', 'null']},
            },
        }},
    },
}


def strict_json(text: str):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('Duplicate review JSON key')
            result[key] = value
        return result
    def invalid_constant(value):
        raise ValueError('Non-finite JSON number')
    return json.loads(text, object_pairs_hook=unique, parse_constant=invalid_constant)


def review_sources(report: dict, *, max_findings: int = MAX_REVIEW_FINDINGS) -> list[dict]:
    """Select bounded report excerpts; imported claims remain unverified."""
    if type(max_findings) is not int or not 1 <= max_findings <= MAX_REVIEW_FINDINGS:
        raise ValueError('Review batch must contain 1..20 findings')
    if not isinstance(report, dict) or report.get('schema') != 'penx-scan-v1':
        raise ValueError('Review requires a penx-scan-v1 collection report')
    if not isinstance(report.get('target'), str) or not 0 < len(report['target']) <= 4096:
        raise ValueError('Invalid review target')
    findings = report.get('findings')
    if not isinstance(findings, list) or len(findings) > 1000:
        raise ValueError('Invalid or oversized finding list')
    sources: list[dict] = []
    seen = set()
    for finding in findings:
        if not isinstance(finding, dict):
            raise ValueError('Invalid source finding')
        identity = finding.get('fingerprint')
        if not isinstance(identity, str) or not re.fullmatch(r'penx-finding-v1:[a-f0-9]{64}', identity):
            raise ValueError('Invalid source fingerprint')
        # Duplicate identities cannot establish an unambiguous evidence source.
        if identity in seen:
            raise ValueError('Duplicate source fingerprint')
        seen.add(identity)
        name, evidence = finding.get('name'), finding.get('raw_evidence', '')
        if not isinstance(name, str) or not isinstance(evidence, str) or len(evidence) > 2000:
            raise ValueError('Invalid source evidence')
        if len(sources) < max_findings:
            source = {'fingerprint': identity, 'name': name[:200],
                      'severity': str(finding.get('severity', 'unknown'))[:20],
                      'evidence': evidence[:1000]}
            # Keep exact excerpts bounded independently from the report file.
            if len(json.dumps(sources + [source], ensure_ascii=True)) <= MAX_PROMPT_CHARS - 6000:
                sources.append(source)
    return sources


def validate_review(text: str, sources: list[dict], *, allowed_scanners: set[str]) -> dict:
    """Validate schema, exact source identities, literal citations and suggestions."""
    from jsonschema import Draft202012Validator
    if not isinstance(text, str) or len(text.encode('utf-8')) > MAX_RESPONSE_BYTES:
        raise ValueError('Review response exceeds 64 KiB')
    value = strict_json(text)
    Draft202012Validator(REVIEW_SCHEMA).validate(value)
    original = {source['fingerprint']: source for source in sources}
    used = set()
    for item in value['reviews']:
        identity = item['fingerprint']
        if identity not in original or identity in used:
            raise ValueError('Unknown or duplicated review finding')
        used.add(identity)
        quote = item['evidence_quote']
        if quote:
            if len(quote.strip()) < 12 or quote not in original[identity]['evidence']:
                raise ValueError('Review citation must exactly match supplied evidence')
        elif item['assessment'] != 'insufficient_evidence':
            raise ValueError('Evidence-free review must remain insufficient_evidence')
        if item['suggested_scanner_key'] is not None and item['suggested_scanner_key'] not in allowed_scanners:
            raise ValueError('Review suggestion expands the recorded scanner selection')
    return value
