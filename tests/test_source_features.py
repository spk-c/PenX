"""Offline regression tests for structured reports, source verification and transport."""
from __future__ import annotations

import json
import unittest
from unittest.mock import Mock, patch

import requests
from jsonschema import ValidationError

import llm
from penx_app.intelligence import source_verification as verify
from penx_app.analysis.llm_client import complete_chat
from penx_app.analysis.structured_output import ANALYSIS_SCHEMA, parse_json_findings, request_structured_report


def sample():
    return {
        "vulnerabilities": [{
            "vuln_name": "CVE-2024-6387 (test only)",
            "severity": "high", "confidence": "possible",
            "port": "22", "service": "ssh", "description": "Version needs validation",
            "evidence": "OpenSSH version marker fixture",
            "fix": "Verify vendor patches", "cve_ids": ["CVE-2024-6387"]
        }],
        "recommendations": [{"vuln_name": "Inventory servers", "description": "Review patch levels"}],
        "exploits": [], "risk_level": "HIGH", "summary": "Example only"
    }


class SourceAndSchemaTests(unittest.TestCase):
    def setUp(self):
        verify._nvd_cache.clear()
        verify._kev_cache = None

    def test_valid_json_schema(self):
        parsed = parse_json_findings(json.dumps(sample()))
        self.assertEqual(parsed["vulnerabilities"][0]["port"], "22")
        self.assertEqual(parse_json_findings("~~~" .replace("~~~", chr(96)*3) +
                        "json\n" + json.dumps(sample()) + "\n" + chr(96)*3)["risk_level"], "HIGH")

    def test_schema_rejects_unsupported_types(self):
        obj = sample()
        obj["risk_level"] = "catastrophic"
        with self.assertRaises(ValidationError):
            parse_json_findings(json.dumps(obj))
        obj = sample()
        obj["vulnerabilities"][0]["confidence"] = "verified"
        with self.assertRaises(ValidationError):
            parse_json_findings(json.dumps(obj))
        obj = sample()
        del obj["vulnerabilities"][0]["evidence"]
        with self.assertRaises(ValidationError):
            parse_json_findings(json.dumps(obj))

    def test_source_lookup_never_marks_target_vulnerable(self):
        calls = []
        def get(url, **kwargs):
            calls.append((url, kwargs))
            response = Mock()
            response.raise_for_status.return_value = None
            if url == verify.NVD_API:
                response.json.return_value = {"vulnerabilities": [
                    {"cve": {"id": "CVE-2024-6387"}}
                ]}
            else:
                response.json.return_value = {"vulnerabilities": [
                    {"cveID": "CVE-2024-6387"}
                ]}
            return response
        finding = sample()["vulnerabilities"][0]
        scan = "Host 10.55.66.77 OpenSSH version marker fixture"
        with patch("penx_app.intelligence.source_verification.requests.get", side_effect=get):
            verify.verify_findings([finding], scan)
        self.assertIn("NVD listed", finding["description"])
        self.assertIn("CISA KEV listed", finding["description"])
        self.assertIn("NOT confirmation", finding["description"])
        self.assertEqual(finding["confidence"], "possible")
        self.assertEqual(calls[0][1]["params"], {"cveId": "CVE-2024-6387"})
        self.assertNotIn("10.55.66.77", repr(calls))

    def test_absent_evidence_downgrades_and_unavailable_is_not_negative(self):
        entry = sample()["vulnerabilities"][0]
        entry["confidence"] = "confirmed"
        with patch("penx_app.intelligence.source_verification.requests.get", side_effect=requests.Timeout()):
            verify.verify_findings([entry], "No matching evidence here")
        self.assertEqual(entry["confidence"], "possible")
        self.assertIn("NVD unavailable", entry["description"])
        self.assertIn("CISA KEV unavailable", entry["description"])

    def test_disabled_sources_make_no_requests(self):
        entry = sample()["vulnerabilities"][0]
        with patch("penx_app.intelligence.source_verification.requests.get") as get:
            self.assertEqual(verify.verify_findings([entry], "irrelevant", enabled=False), [entry])
            get.assert_not_called()
        self.assertNotIn("source_checks", entry)

    def test_structured_retry_on_unsupported_schema(self):
        err = requests.HTTPError(response=Mock(status_code=400))
        with patch("penx_app.analysis.structured_output.complete_chat",
                   side_effect=[err, ("local-model", json.dumps(sample()))]) as call:
            data = request_structured_report("raw", "analysis", "", url="http://localhost:8080/v1/chat/completions",
                                             models_url="http://localhost:8080/v1/models", model_name="local")
        self.assertEqual(data["risk_level"], "HIGH")
        self.assertEqual(call.call_count, 2)
        self.assertEqual(call.call_args_list[0].kwargs["response_format"]["type"], "json_schema")
        self.assertEqual(call.call_args_list[1].kwargs["response_format"]["type"], "json_object")

    def test_transport_passes_schema(self):
        response = Mock()
        response.json.return_value = {"choices": [{"message": {"content": "ok"}}]}
        response.raise_for_status.return_value = None
        with patch("penx_app.analysis.llm_client.requests.post", return_value=response) as post:
            complete_chat([{"role": "user", "content": "hi"}],
                          url="http://localhost/v1/chat/completions",
                          models_url="http://localhost/v1/models",
                          model_name="local", response_format={"type": "json_object"})
        self.assertEqual(post.call_args.kwargs["json"]["response_format"]["type"], "json_object")

    def test_main_analysis_uses_schema_without_executing_json_directives(self):
        result = sample()
        with patch("llm.STRUCTURED_MODE", "auto"), patch("llm.VERIFY_SOURCES", False), \
             patch("llm.load_correction_rules", return_value=""), \
             patch("llm.ask_llm", return_value="RISK_LEVEL: LOW\nSUMMARY: First pass"), \
             patch("llm.self_review", return_value={"review":"", "adjusted_risk":"", "flags":[]}), \
             patch("llm.request_structured_report", return_value=result), \
             patch("llm.verify_findings", side_effect=lambda findings, *_a, **_kw: findings):
            data = llm.analyse_target("example.test", "OpenSSH version marker fixture")
        self.assertEqual(data["risk_level"], "HIGH")
        self.assertEqual(data["vulnerabilities"][0]["vuln_name"], "CVE-2024-6387 (test only)")
        self.assertIn("[STRUCTURED JSON REPORT]", data["full_response"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
