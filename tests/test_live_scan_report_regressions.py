"""Regression tests for issues found in the authorized shirtgeklebt.net live test.

All fixtures are local and deterministic: never contact a public target or an LLM.
"""
from __future__ import annotations

import io
import json
import unittest
from unittest.mock import patch

import requests

from penx_app.analysis.llm_client import complete_chat
from penx_app.intelligence.source_verification import verify_findings


class LiveScanReportRegressions(unittest.TestCase):
    def test_stream_decodes_utf8_bytes_independent_of_http_charset_guess(self):
        """An SSE stream lacking charset must not turn UTF-8 into mojibake."""
        fragments = ["Risk — ", "Schwachstelle: ä, ö, ü; €; 🔍"]
        events = [
            {"choices": [{"delta": {"content": fragment}}]}
            for fragment in fragments
        ] + [
            {"choices": [{"delta": {}, "finish_reason": "stop"}]}
        ]
        payload = b"".join(
            b"data: " + json.dumps(event, ensure_ascii=False).encode("utf-8") + b"\r\n\r\n"
            for event in events
        ) + b"data: [DONE]\r\n\r\n"

        response = requests.Response()
        response.status_code = 200
        response.headers["Content-Type"] = "text/event-stream"
        # requests can select ISO-8859-1 for text/* without a charset;
        # this used to corrupt em dashes in persisted model responses.
        response.encoding = "ISO-8859-1"
        response.raw = io.BytesIO(payload)
        callbacks = []

        with patch("penx_app.analysis.llm_client.requests.post", return_value=response) as post:
            model_id, final = complete_chat(
                [{"role": "user", "content": "Authorized test fixture"}],
                url="http://127.0.0.1:8080/v1/chat/completions",
                models_url="http://127.0.0.1:8080/v1/models",
                model_name="test-local-model",
                stream_callback=callbacks.append,
            )
        self.assertEqual(model_id, "test-local-model")
        self.assertEqual(final, "".join(fragments))
        self.assertEqual(callbacks, fragments)
        self.assertNotIn("â\x80\x94", final)
        self.assertTrue(post.call_args.kwargs["stream"])

    def test_source_checks_without_cve_are_readable_and_preserve_evidence(self):
        evidence = "Strict-Transport-Security: max-age=2592000"
        finding = {
            "vuln_name": "Hardening recommendation",
            "confidence": "possible",
            "description": "Review response headers.",
            "evidence": evidence,
        }
        with patch("penx_app.intelligence.source_verification.requests.get") as get:
            result = verify_findings([finding], "HEADERS: " + evidence)[0]
        get.assert_not_called()
        self.assertEqual(result["confidence"], "possible")
        self.assertIn("supporting text found in original scan output", result["description"])
        self.assertNotIn("quoted exactly", result["description"])
        self.assertNotIn("No CVE identifier supplied.", result["description"])
        self.assertEqual(result["description"].count("Reference checks"), 1)

    def test_absent_source_evidence_keeps_conservative_downgrade(self):
        finding = {
            "vuln_name": "Header mismatch",
            "confidence": "confirmed",
            "description": "Review response headers.",
            "evidence": "Strict-Transport-Security: max-age=2592000",
        }
        result = verify_findings([finding], "No matching scanner record")[0]
        self.assertEqual(result["confidence"], "possible")
        self.assertIn("NOT confirmed in original scan", result["description"])
        self.assertNotIn("No CVE identifier supplied.", result["description"])

    def test_real_cve_still_has_nvd_applicability_and_kev_status(self):
        finding = {
            "vuln_name": "CVE-2024-6387 possible",
            "confidence": "possible",
            "description": "Check affected version.",
            "evidence": "OpenSSH version 9.2p1 service observed",
        }
        with (
            patch("penx_app.intelligence.source_verification.lookup_nvd", return_value="listed"),
            patch("penx_app.intelligence.source_verification.verify_nvd_applicability",
                  return_value="unknown (version/configuration uncertain)"),
            patch("penx_app.intelligence.source_verification.load_cisa_kev", return_value=set()),
        ):
            result = verify_findings([finding], finding["evidence"])[0]
        self.assertIn("CVE-2024-6387: NVD listed", result["description"])
        self.assertIn("observed-version applicability", result["description"])
        self.assertIn("CVE-2024-6387: CISA KEV not-listed", result["description"])
        self.assertNotIn("quoted exactly", result["description"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
