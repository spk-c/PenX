"""Offline regression tests for audit issue #62 and safe Groq fallback handling."""
from __future__ import annotations

from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch
from urllib.error import HTTPError, URLError
from email.message import Message
import json

from scripts import issue_triage as it


def audit_issue():
    return {
        "number": 62,
        "title": "Detailliertes Bug- & Security-Review: Installer, penx.py, Secrets und Tests",
        "body": """## Review-Scope
- [ ] penx.py: shell=True, eval/exec
- [ ] install_scanners_windows.py: HTTPS and hashes
- [ ] windows_python_setup.py: PATH changes
- [ ] Git-Historie: secrets

## Akzeptanzkriterien
- [ ] Kritische Befunde mit Severity und Reproduktion
- [ ] CI führt Tests und Secret Scanning aus
""",
    }


def http_error(code, *, retry_after=None, secret="sk-dummy-secret"):
    headers = Message()
    if retry_after is not None:
        headers["Retry-After"] = str(retry_after)
    return HTTPError("https://api.groq.com/v1/secret/" + secret,
                     code, "provider returned " + secret, headers, None)


class Issue62TriageTests(TestCase):
    def test_security_audit_checklist_is_not_a_bug(self):
        self.assertTrue(it.is_audit_request(audit_issue()))
        result = it.audit_review(audit_issue())
        self.assertEqual(result["verdict"], "audit")
        self.assertEqual(result["verification"], "none")
        rendered = it.comment("SLP-DEV1/PenX", result)
        self.assertIn("audit requested", rendered)
        self.assertIn("No AI code review or audit was completed", rendered)
        self.assertNotIn("Source inspection only", rendered)

    def test_reproducible_bug_audit_does_not_match(self):
        issue = {
            "title": "[Bug audit] Six reproducible correctness defects",
            "body": "## Reproduction\n- [ ] one\n- [ ] two\n- [ ] three\n"
                    "This security review demonstrates concrete failures.",
        }
        self.assertFalse(it.is_audit_request(issue))
        self.assertFalse(it.is_audit_request({
            "title": "Reproducible crash in installer after file-not-found",
            "body": "Actual: crash, expected: clean exit",
        }))

    def test_review_skips_groq_and_source_collection_for_audit(self):
        with patch.object(it, "request_json", return_value=audit_issue()) as request, \
             patch.object(it, "code_context", side_effect=AssertionError("source parsed")), \
             patch.object(it, "model_review", side_effect=AssertionError("Groq called")):
            result = it.review("SLP-DEV1/PenX", 62, "fake-token", Path("/unused"))
        self.assertEqual(result["verdict"], "audit")
        self.assertEqual(request.call_count, 1)
        self.assertEqual(it.LABELS["audit"][0], "triage:audit")

    def test_retry_429_then_success(self):
        with patch.object(it, "request_json", side_effect=[
            http_error(429, retry_after=3), {"choices": [1]}]) as api, \
             patch.object(it.time, "sleep") as sleep:
            result = it.request_groq({"hello": "world"}, "secret")
        self.assertEqual(result, {"choices": [1]})
        self.assertEqual(api.call_count, 2)
        sleep.assert_called_once_with(3)

    def test_no_retry_on_large_retry_after(self):
        with patch.object(it, "request_json", side_effect=http_error(429, retry_after=60)) as api, \
             patch.object(it.time, "sleep") as sleep:
            with self.assertRaises(HTTPError):
                it.request_groq({}, "secret")
        api.assert_called_once()
        sleep.assert_not_called()

    def test_no_retry_401_or_secret_logging(self):
        exc = http_error(401, secret="sk-top-secret-do-not-print")
        self.assertEqual(it.groq_error_category(exc), "HTTP 401: credentials or access denied")
        with patch.object(it, "request_json", side_effect=exc) as api, \
             patch.object(it.time, "sleep") as sleep:
            with self.assertRaises(HTTPError):
                it.request_groq({}, "secret")
        api.assert_called_once()
        sleep.assert_not_called()
        self.assertNotIn("sk-top-secret", it.groq_error_category(exc))

    def test_three_attempt_limit_for_503(self):
        with patch.object(it, "request_json", side_effect=http_error(503)) as api, \
             patch.object(it.time, "sleep") as sleep:
            with self.assertRaises(HTTPError):
                it.request_groq({}, "secret")
        self.assertEqual(api.call_count, 3)
        self.assertEqual([x.args[0] for x in sleep.call_args_list], [1, 2])

    def test_categories_do_not_reflect_sensitive_errors(self):
        sample = {
            "rate": (http_error(429), "HTTP 429"),
            "network": (URLError("sk-supersecret"), "network"),
            "timeout": (TimeoutError("sk-supersecret"), "timeout"),
            "json": (json.JSONDecodeError("sk-supersecret", "private", 0), "invalid JSON"),
            "incomplete": (it.ModelReviewError("incomplete model response", "private"), "incomplete"),
            "malformed": (KeyError("sk-supersecret"), "response structure"),
        }
        for name, (exc, label) in sample.items():
            with self.subTest(name=name):
                self.assertIn(label, it.groq_error_category(exc))
                self.assertNotIn("sk-supersecret", it.groq_error_category(exc))
                self.assertNotIn("private", it.groq_error_category(exc))

    def test_model_failure_is_sanitized_and_does_not_claim_verification(self):
        issue = {"number": 4, "title": "Installer fails when missing", "body": "Error is reproducible"}
        def fake_request(url, token):
            return issue if "/issues/4" in url else []
        output = StringIO()
        with patch.object(it, "request_json", side_effect=fake_request), \
             patch.object(it, "code_context", return_value=("", {})), \
             patch.object(it, "model_review", side_effect=http_error(429, secret="sk-never-log")), \
             patch.dict(it.os.environ, {"PENX_TRIAGE_GROQ_API_KEY": "fake-test-key"}):
            with redirect_stdout(output):
                result = it.review("SLP-DEV1/PenX", 4, "fake-token", Path("/unused"))
        self.assertEqual(result["verdict"], "deferred")
        self.assertIn("automatic re-review pending", result["comment"].lower())
        self.assertIn("HTTP 429", result["comment"])
        self.assertIn("No AI code review or audit was completed", result["comment"])
        self.assertNotIn("sk-never-log", result["comment"] + output.getvalue())

    def test_markdown_link_has_no_python_escape_warning(self):
        review = {"verdict": "likely-valid", "summary": "supported", "reason": "source",
                  "evidence": [{"file": "src/tools.py", "line": 44}],
                  "missing": [], "findings": [], "duplicate_issue": None, "next_step": ""}
        rendered = it.comment("SLP-DEV1/PenX", review)
        self.assertIn("[" + chr(96) + "src/tools.py:44" + chr(96) + "]", rendered)
        source = (Path(__file__).resolve().parents[1] / "scripts" / "issue_triage.py").read_text()
        self.assertNotIn(chr(92) + chr(96), source)

    def test_owner_only_re_review_trigger_preserves_permissions(self):
        workflow = (Path(__file__).resolve().parents[1] / ".github" /
                    "workflows" / "issue-triage.yml").read_text()
        self.assertIn("issue_comment:", workflow)
        self.assertIn("types: [created]", workflow)
        self.assertIn("github.event.comment.body == '/penx-triage'", workflow)
        self.assertIn("github.event.comment.author_association == 'OWNER'", workflow)
        self.assertIn("github.event.issue.pull_request == null", workflow)
        review, publish = workflow.split("\n  publish:", 1)
        self.assertNotIn("issues: write", review)
        self.assertIn("issues: write", publish)


if __name__ == "__main__":
    import unittest
    unittest.main(verbosity=2)
