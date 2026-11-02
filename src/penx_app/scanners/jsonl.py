"""Decode one untrusted scanner object without ambiguous fields or constants."""
import json


def _unique_fields(pairs):
    fields = {}
    for key, value in pairs:
        if key in fields:
            raise ValueError("Duplicate scanner JSON field")
        fields[key] = value
    return fields


def _reject_constant(value):
    raise ValueError("Non-finite scanner JSON number")


def load_record(raw: str) -> dict:
    record = json.loads(raw, object_pairs_hook=_unique_fields,
                        parse_constant=_reject_constant)
    if not isinstance(record, dict):
        raise ValueError("Scanner JSON record must be an object")
    return record
