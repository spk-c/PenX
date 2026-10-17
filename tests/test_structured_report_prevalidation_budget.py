"""Enforce structured response budgets before expensive JSON/schema traversal.

All inputs are synthetic; no model endpoint or scanner is contacted.
"""
from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from jsonschema import ValidationError

from penx_app.analysis import structured_output as output


def valid():
    return {
        "vulnerabilities": [],
        "recommendations": [],
        "exploits": [],
        "risk_level": "LOW",
        "summary": "fixture",
    }


class StructuredResponseInputBudgetTests(unittest.TestCase):
    def test_oversized_model_output_fails_before_json_parser(self):
        text = " " * (output.MAX_STRUCTURED_RESPONSE_CHARS + 1)
        with patch.object(output.json, "loads",
                          side_effect=AssertionError("must not decode")):
            with self.assertRaisesRegex(ValueError, "exceeds"):
                output.parse_json_findings(text)

    def test_non_string_payload_fails_before_parsing(self):
        for bad in (None, {}, [], 0):
            with self.subTest(value=repr(bad)), self.assertRaises(ValueError):
                output.parse_json_findings(bad)

    def test_too_many_findings_fail_before_schema_validation(self):
        for key in ("vulnerabilities", "recommendations", "exploits"):
            data = valid()
            data[key] = [{} for _ in range(output.MAX_FINDINGS_PER_CATEGORY + 1)]
            with self.subTest(key=key), patch.object(
                output, "validate", side_effect=AssertionError("schema scan")
            ), self.assertRaisesRegex(ValueError, "maximum 100"):
                output.parse_json_findings(json.dumps(data))

    def test_valid_json_and_markdown_fences_are_unchanged(self):
        encoded = json.dumps(valid())
        self.assertEqual(output.parse_json_findings(encoded), valid())
        fence = chr(96) * 3
        self.assertEqual(output.parse_json_findings(
            fence + "json\n" + encoded + "\n" + fence
        ), valid())

    def test_valid_size_but_invalid_schema_is_still_rejected(self):
        data = valid()
        data["risk_level"] = "INVALID"
        with self.assertRaises(ValidationError):
            output.parse_json_findings(json.dumps(data))

    def test_existing_evidence_size_limit_still_applies(self):
        data = valid()
        data["vulnerabilities"] = [{
            "vuln_name": "synthetic",
            "severity": "low",
            "confidence": "possible",
            "port": "",
            "service": "",
            "description": "fixture",
            "evidence": "E" * 3001,
            "fix": "fixture",
            "cve_ids": [],
        }]
        with self.assertRaisesRegex(ValueError, "evidence length"):
            output.parse_json_findings(json.dumps(data))


if __name__ == "__main__":
    unittest.main()
