"""Offline security and decision tests for automated GitHub issue triage."""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import URLError

from scripts import issue_triage as it


class IssueTriageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="penx_issue_triage_")
        self.root = Path(self.temp.name)
        (self.root / "src").mkdir()
        (self.root / "src" / "scanner.py").write_text(
            "def scan_target(target):\n"
            "    result = run_nmap(target)\n"
            "    if result:\n"
            "        return result\n"
            "    return 'empty'\n", encoding="utf-8"
        )

    def tearDown(self):
        self.temp.cleanup()

    def test_paths_must_be_inside_allowlist(self):
        for invalid in ("../.env", ".env", "/etc/passwd", "src/../.env",
                        "src\\scanner.py", "nothing.py", ".github/secrets/foo.txt"):
            with self.subTest(invalid=invalid):
                self.assertIsNone(it.allowed_file(self.root, invalid))
        self.assertIsNotNone(it.allowed_file(self.root, "src/scanner.py"))

    def test_code_snippets_carry_exact_line_references(self):
        issue = {"title": "Scanner returns empty data", "body": "Bug in src/scanner.py"}
        excerpts, actual = it.code_context(self.root, issue)
        self.assertIn("FILE src/scanner.py", excerpts)
        self.assertIn("L2:     result = run_nmap(target)", excerpts)
        self.assertEqual(actual["src/scanner.py"][2], "    result = run_nmap(target)")

    def test_named_new_scan_returns_are_found_even_after_generic_keyword_hits(self):
        # Regression for issue #40: the old excerpt picker read penx.py but
        # omitted the named function despite a concrete issue reference.
        (self.root / "penx.py").write_text(
            "\n".join(f"message_{i} = 'return error from code'" for i in range(130))
            + "\ndef new_scan():\n"
              "    if not llm_auth_preflight():\n"
              "        return\n"
              "    if invalid_target():\n"
              "        return False\n"
              "    if analysis_failed():\n"
              "        return\n",
            encoding="utf-8",
        )
        issue = {
            "title": "Mixed return types in new_scan()",
            "body": "Finding #1: new_scan() (`penx.py`) returns None on LLM "
                    "failure but False on cancel. Confirm the actual code.",
        }
        excerpts, indexed = it.code_context(self.root, issue)
        self.assertIn("FILE penx.py", excerpts)
        self.assertIn("def new_scan():", excerpts)
        self.assertIn("        return False", excerpts)
        self.assertIn("return False", excerpts)
        self.assertIn("new_scan():", "\n".join(indexed["penx.py"].values()))
        self.assertTrue(any(line.strip() == "return" for line in indexed["penx.py"].values()))
        self.assertTrue(any(line.strip() == "return False" for line in indexed["penx.py"].values()))
        self.assertLessEqual(len(excerpts), it.MAX_FILE_CHARS)

    def test_filename_only_reference_resolves_to_allowlisted_src(self):
        (self.root / "src" / "db_backend.py").write_text(
            "def get_connection():\n    return 'sqlite'\n", encoding="utf-8"
        )
        issue = {"title": "MariaDB migration footgun",
                 "body": "Check db_backend.py and the optional MariaDB migrations."}
        excerpts, indexed = it.code_context(self.root, issue)
        self.assertIn("FILE src/db_backend.py", excerpts)
        self.assertIn("src/db_backend.py", indexed)

    def test_explicit_root_docs_and_migrations_are_allowlisted(self):
        (self.root / "migrations").mkdir()
        (self.root / "migrations" / "README.md").write_text(
            "Optional MariaDB schema changes\n", encoding="utf-8"
        )
        (self.root / "WINDOWS.md").write_text(
            "Windows and MariaDB installation instructions\n", encoding="utf-8"
        )
        issue = {"title": "MariaDB docs", "body": "See WINDOWS.md and migrations/README.md"}
        excerpts, indexed = it.code_context(self.root, issue)
        self.assertIn("FILE WINDOWS.md", excerpts)
        self.assertIn("FILE migrations/README.md", excerpts)
        self.assertIn("WINDOWS.md", indexed)
        self.assertIn("migrations/README.md", indexed)

    def test_every_citable_line_is_actually_in_the_model_context(self):
        lines = ["def important():", "    pass"]
        lines += [f"noise_{i} = 'issue return issue failure'" for i in range(200)]
        (self.root / "penx.py").write_text("\n".join(lines) + "\n", encoding="utf-8")
        excerpt, evidence = it.code_context(
            self.root, {"title": "important()", "body": "Inspect penx.py return paths"}
        )
        for _path, indexed in evidence.items():
            for line_no, line in indexed.items():
                self.assertIn(f"L{line_no}: {line[:230]}", excerpt)
        self.assertLessEqual(len(excerpt), it.MAX_FILE_CHARS)

    def test_reject_hallucinated_model_citations(self):
        review = {"verdict": "likely-valid", "category": "bug", "summary": "Broken",
                  "reason": "Evidence", "evidence": [
                      {"file": "src/scanner.py", "line": 2, "quote": "nonexistent_call()"}
                  ], "missing": [], "next_step": "Fix it"}
        clean = it.validate(review, [], {"src/scanner.py": {
            2: "    result = run_nmap(target)",
        }})
        self.assertEqual(clean["verdict"], "needs-info")
        self.assertEqual(clean["evidence"], [])

    def test_accept_grounded_line_but_only_likely_valid(self):
        review = {"verdict": "likely-valid", "category": "bug",
                  "summary": "Scanner reports errors as success",
                  "reason": "Raw result checked for truthiness only",
                  "evidence": [{"file": "src/scanner.py", "line": 3, "quote": "if result:"}],
                  "missing": [], "next_step": "Add a failing mock test"}
        valid = it.validate(review, [], {"src/scanner.py": {3: "    if result:"}})
        self.assertEqual(valid["verdict"], "likely-valid")
        msg = it.comment("SLP-DEV1/PenX", valid)
        self.assertIn("Likely valid (not confirmed)", msg)
        self.assertIn("src/scanner.py:3", msg)
        self.assertIn("Only a maintainer can confirm", msg)
        self.assertIn(it.MARKER, msg)

    def test_feature_requests_are_not_labeled_verified_bugs(self):
        review = {"verdict": "likely-valid", "category": "feature",
                  "evidence": [{"file": "src/scanner.py", "line": 2,
                                "quote": "run_nmap(target)"}]}
        self.assertEqual(it.validate(review, [], {"src/scanner.py": {
            2: "    result = run_nmap(target)",
        }})["verdict"], "proposal")

    def test_duplicate_detection_is_provisional(self):
        report = {"number": 17, "title": "Windows scanner crashes when Nmap is missing"}
        others = [
            {"number": 16, "title": "Windows scanner crashes when Nmap is missing"},
            {"number": 15, "title": "Completely unrelated feature request"},
            {"number": 14, "title": "Windows scanner crashes when Nmap is missing",
             "pull_request": {"url": "pull"}},
        ]
        found = it.duplicates(report, others)
        self.assertEqual([x["number"] for x in found], [16])
        with patch.dict(os.environ, {"PENX_TRIAGE_GROQ_API_KEY": ""}), \
             patch.object(it, "request_json", side_effect=[report, others]), \
             patch.object(it, "model_review", side_effect=AssertionError("AI not configured")):
            outcome = it.review("SLP-DEV1/PenX", 17, "fake-token", self.root)
        # Sparse reports still require reproduction steps; similarity alone
        # must not override the needs-info outcome with a duplicate label.
        self.assertEqual(outcome["verdict"], "needs-info")
        self.assertIn("Related issue (not confirmed duplicate)", outcome["comment"])
        self.assertIn("/issues/16", outcome["comment"])

    def test_unverified_model_error_is_not_a_negative_maintenance_verdict(self):
        issue = {"number": 9, "title": "Runtime crash in src/scanner.py", "body": "Steps"}
        with patch.dict(os.environ, {"PENX_TRIAGE_GROQ_API_KEY": "fake-groq-key"}), \
             patch.object(it, "request_json", side_effect=[issue, []]), \
             patch.object(it, "model_review", side_effect=URLError("model unavailable")):
            report = it.review("SLP-DEV1/PenX", 9, "fake-token", self.root)
        self.assertEqual(report["verdict"], "unverified")
        self.assertIn("not a judgment about the report", report["comment"])

    def test_unconfigured_ai_provides_deterministic_triage_without_claiming_a_bug(self):
        issue = {"number": 9, "title": "[Bug] Bad reply in PenX",
                 "body": "Steps to reproduce: choose New Scan. Expected: a report. Actual: none."}
        with patch.dict(os.environ, {"PENX_TRIAGE_GROQ_API_KEY": ""}), \
             patch.object(it, "request_json", side_effect=[issue, []]), \
             patch.object(it, "model_review", side_effect=AssertionError("No AI key")):
            report = it.review("SLP-DEV1/PenX", 9, "fake-token", self.root)
        self.assertEqual(report["verdict"], "unverified")
        self.assertIn("not been established", report["comment"])

    def test_unconfigured_ai_requests_reproduction_steps(self):
        issue = {"number": 10, "title": "Crash in scanner", "body": "Not working"}
        with patch.dict(os.environ, {"PENX_TRIAGE_GROQ_API_KEY": ""}), \
             patch.object(it, "request_json", side_effect=[issue, []]):
            report = it.review("SLP-DEV1/PenX", 10, "fake-token", self.root)
        self.assertEqual(report["verdict"], "needs-info")
        self.assertIn("reproduction steps", report["comment"])

    def test_groq_free_qwen_json_request_has_no_secret_in_prompt(self):
        issue = {"title": "Scanner reports success after error",
                 "body": "Steps to reproduce: start scan. Expected: failure."}
        similar = [{"number": 11, "title": "Scanner error"}]
        with patch.dict(os.environ, {"PENX_TRIAGE_MODEL": ""}), \
             patch.object(it, "request_json", return_value={
                 "choices": [{"finish_reason": "stop", "message": {
                     "content": '{"category":"bug","verdict":"needs-info","evidence":[]}'
                 }}]
             }) as api:
            result = it.model_review(issue, similar, "FILE src/tools.py:\\nL42: return output",
                                     "mock-secret-do-not-leak")
        self.assertEqual(result["verdict"], "needs-info")
        self.assertEqual(api.call_args.args[0], "https://api.groq.com/openai/v1/chat/completions")
        self.assertEqual(api.call_args.args[1], "mock-secret-do-not-leak")
        payload = api.call_args.kwargs["payload"]
        self.assertEqual(payload["model"], "qwen/qwen3.8-27b")
        self.assertEqual(payload["response_format"], {"type": "json_object"})
        self.assertEqual(payload["reasoning_effort"], "none")
        self.assertEqual(payload["reasoning_format"], "hidden")
        self.assertNotIn("mock-secret-do-not-leak", str(payload))

    def test_alternate_groq_model_does_not_receive_qwen_reasoning_options(self):
        with patch.dict(os.environ, {"PENX_TRIAGE_MODEL": "openai/gpt-oss-20b"}), \
             patch.object(it, "request_json", return_value={
                 "choices": [{"finish_reason": "stop", "message": {
                     "content": '{"verdict":"unverified"}'
                 }}]
             }) as api:
            it.model_review({"title": "Bug", "body": ""}, [], "", "test-key")
        payload = api.call_args.kwargs["payload"]
        self.assertEqual(payload["model"], "openai/gpt-oss-20b")
        self.assertNotIn("reasoning_effort", payload)
        self.assertNotIn("reasoning_format", payload)

    def test_incomplete_groq_answer_never_becomes_an_issue_verdict(self):
        with patch.object(it, "request_json", return_value={
            "choices": [{"finish_reason": "length", "message": {
                "content": '{"verdict":"likely-valid","evidence":[]}'
            }}]
        }):
            with self.assertRaisesRegex(ValueError, "incomplete"):
                it.model_review({"title": "bug", "body": ""}, [], "", "fake-key")

    def test_groq_api_is_only_allowed_provider_host(self):
        with self.assertRaises(ValueError):
            it.request_json("https://api.groq.com.evil.example/v1/chat/completions",
                            "mock-secret")
        with self.assertRaises(ValueError):
            it.request_json("https://api.openai.com/v1/chat/completions",
                            "mock-secret")

    def test_model_invalid_duplicate_reference_is_rejected(self):
        result = it.validate({
            "verdict": "possible-duplicate", "duplicate_issue": 12345,
            "evidence": [], "summary": "duplicate", "reason": "similar"
        }, [{"number": 18, "score": 0.7}], {})
        self.assertEqual(result["verdict"], "unverified")
        self.assertIsNone(result["duplicate_issue"])

    def test_accidentally_pasted_credentials_are_redacted(self):
        raw = ("PENX_GITHUB_ADVISORY_TOKEN=github_pat_" + "abc123XYZ0" * 5 +
               " and Bearer 0123456789abcdefghijklmnopqrstuvwxyz")
        safe = it.redact_secrets(raw)
        self.assertNotIn("github_pat_", safe)
        self.assertNotIn("0123456789abcdefghijklmnopqrstuvwxyz", safe)
        self.assertIn("[REDACTED", safe)
        self.assertNotIn("github_pat_", it.safe_text(raw))

    def test_model_untrusted_text_is_escaped(self):
        result = it.validate({
            "verdict": "needs-info", "summary": "<img src=x> @maintainer",
            "reason": "Need details", "evidence": [], "missing": [],
        }, [], {})
        body = it.comment("SLP-DEV1/PenX", result)
        self.assertNotIn("<img", body)
        self.assertNotIn("@maintainer", body)
        self.assertIn("&lt;img", body)

    def test_publish_creates_only_label_and_comment(self):
        report = {"repo": "SLP-DEV1/PenX", "issue_number": 9,
                  "verdict": "needs-info", "comment": it.MARKER + "\nNeeds logs"}
        calls = []

        def fake_api(url, _token, *, method="GET", payload=None, **_):
            calls.append((method, url, payload))
            if "/issues/9/labels?" in url:
                return [{"name": "bug"}]
            if url.endswith("/issues/9/comments?per_page=100"):
                return []
            return {}

        with patch.object(it, "request_json", side_effect=fake_api):
            it.publish(report, "fake-token", "SLP-DEV1/PenX", 9)
        posts = [(method, url) for method, url, _ in calls if method != "GET"]
        self.assertEqual(len(posts), 3)
        self.assertTrue(any(url.endswith("/labels") for _, url in posts))
        self.assertTrue(any(url.endswith("/issues/9/labels") for _, url in posts))
        self.assertTrue(any(url.endswith("/issues/9/comments") for _, url in posts))
        self.assertFalse(any(url.endswith("/issues/9") for _, url in posts))

    def test_publish_updates_bot_comment_without_duplicates(self):
        report = {"repo": "SLP-DEV1/PenX", "issue_number": 9,
                  "verdict": "likely-valid", "comment": it.MARKER + "\nEvidence"}
        calls = []

        def fake_api(url, _token, *, method="GET", payload=None, **_):
            calls.append((method, url))
            if "/issues/9/labels?" in url:
                return [{"name": "triage:likely-valid"}]
            if url.endswith("/issues/9/comments?per_page=100"):
                return [{"id": 77, "body": it.MARKER + " older",
                         "user": {"login": "github-actions[bot]"}}]
            return {}

        with patch.object(it, "request_json", side_effect=fake_api):
            it.publish(report, "fake-token", "SLP-DEV1/PenX", 9)
        self.assertEqual([method for method, _ in calls if method != "GET"],
                         ["PATCH"])
        self.assertTrue(calls[-1][1].endswith("/issues/comments/77"))

    def test_publish_rejects_wrong_issue_and_arbitrary_status(self):
        good = {"repo": "SLP-DEV1/PenX", "issue_number": 9,
                "verdict": "likely-valid", "comment": it.MARKER + " body"}
        with patch.object(it, "request_json", side_effect=AssertionError("Called GitHub")):
            with self.assertRaises(ValueError):
                it.publish(good, "token", "SLP-DEV1/PenX", 10)
            with self.assertRaises(ValueError):
                it.publish({**good, "verdict": "close-now"}, "token",
                           "SLP-DEV1/PenX", 9)

    def test_review_job_output_base64_and_manual_issue_number(self):
        with tempfile.TemporaryDirectory() as tmp:
            event = Path(tmp, "event.json")
            event.write_text(json.dumps({"inputs": {"issue_number": 9}}), encoding="utf-8")
            output = Path(tmp, "output.txt")
            report = {"repo": "SLP-DEV1/PenX", "issue_number": 9,
                      "verdict": "needs-info", "comment": it.MARKER + " body"}
            with patch.dict(os.environ, {
                "GITHUB_REPOSITORY": "SLP-DEV1/PenX", "GITHUB_EVENT_PATH": str(event),
                "GITHUB_TOKEN": "fake-token", "GITHUB_OUTPUT": str(output)
            }), patch.object(it, "review", return_value=report), \
                 patch.object(it.sys, "argv", ["issue_triage.py", "review"]):
                self.assertEqual(it.main(), 0)
            outputs = dict(line.split("=", 1) for line in
                           output.read_text(encoding="utf-8").splitlines())
            self.assertEqual(outputs["issue_number"], "9")
            self.assertEqual(json.loads(base64.b64decode(outputs["report"])), report)

    def test_workflow_separates_model_access_and_write_permissions(self):
        workflow = Path(__file__).resolve().parents[1] / ".github/workflows/issue-triage.yml"
        yml = workflow.read_text(encoding="utf-8")
        self.assertIn("types: [opened]", yml)
        review_job, publish_job = yml.split("\n  publish:", 1)
        self.assertNotIn("issues: write", review_job)
        self.assertIn("PENX_TRIAGE_GROQ_API_KEY: " + "${{ secrets.PENX_TRIAGE_GROQ_API_KEY }}", review_job)
        self.assertIn("issues: write", publish_job)
        self.assertNotIn("PENX_TRIAGE_GROQ_API_KEY:", publish_job)
        self.assertNotIn("models: read", yml)
        self.assertNotIn("pull_request_target:", yml)


if __name__ == "__main__":
    unittest.main(verbosity=2)
