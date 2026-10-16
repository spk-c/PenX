"""Regression coverage for misleading PenX issue-bot replies and Groq backlog.

Pure offline tests: never contact GitHub, Groq, or scanned hosts.
"""
from __future__ import annotations

from pathlib import Path
from urllib.error import HTTPError
from unittest import TestCase
from unittest.mock import patch

from scripts import issue_triage as it


class TriageReplyQualityTests(TestCase):
    def test_reproduced_four_bug_report_is_not_generic_audit(self):
        issue = {
            "number": 134,
            "title": "[Bug audit] Four edge-case regressions in Katana, WhatWeb, report deletion and NVD cache",
            "body": ("## 1. Katana malformed URL\n"
                     "Reproduction: malformed port and valid URL.\n"
                     "Regression test: assert valid output preserved.\n"
                     "src/penx_app/scanners/tools.py\n"
                     "## Acceptance criteria\n"
                     "- [ ] Test\n- [ ] Fix\n- [ ] Review"),
        }
        self.assertFalse(it.is_audit_request(issue))

    def test_cve_provider_crash_is_bug_not_audit(self):
        issue = {
            "number": 135,
            "title": "[Audit] Malformed CVE provider payloads crash discovery",
            "body": ("Deterministic reproductions: src/penx_app/intelligence/cve_engine.py "
                     "nvd_candidates() calls .get() on invalid records.\n"
                     "Regression test: array response does not crash.\n"
                     "- [ ] Add test\n- [ ] Fix bug\n- [ ] Check warnings"),
        }
        self.assertFalse(it.is_audit_request(issue))

    def test_broad_security_checklist_remains_audit(self):
        issue = {
            "title": "Security review: installers, supply chain and CI",
            "body": "Checklist:\n- [ ] Windows\n- [ ] CI\n- [ ] Secrets\n",
        }
        self.assertTrue(it.is_audit_request(issue))

    def test_claimed_nonexistent_isinstance_guard_downgrades_verdict(self):
        review = {
            "verdict": "likely-valid", "category": "audit",
            "summary": "OSV validates the top-level object",
            "reason": "osv_candidates checks isinstance(obj, dict) before using .get().",
            "evidence": [{"file": "src/cve_engine.py", "line": 4,
                          "quote": "obj = response.json()"}],
            "findings": [{"id": 1, "status": "contradicted",
                          "reason": "osv_candidates checks isinstance(obj, dict)",
                          "evidence": []}],
        }
        code = {"src/cve_engine.py": {4: "    obj = response.json()",
                                        5: "    for vuln in obj.get('vulns', []):"}}
        result = it.validate(review, [], code)
        self.assertEqual(result["verdict"], "unverified")
        self.assertIn("not supported", result["summary"])

    def test_negative_observation_about_missing_guard_is_allowed(self):
        review = {"verdict": "likely-valid", "category": "bug",
                  "reason": "osv_candidates does not check isinstance(obj, dict).",
                  "evidence": [{"file": "src/cve_engine.py", "line": 4,
                                "quote": "obj = response.json()"}]}
        code = {"src/cve_engine.py": {4: "    obj = response.json()"}}
        result = it.validate(review, [], code)
        self.assertEqual(result["verdict"], "likely-valid")

    def test_explicit_audit_category_does_not_erase_supported_findings(self):
        review = {"verdict": "audit", "category": "audit",
                  "reason": "Calls .get on unchecked provider records",
                  "findings": [{"id": 1, "status": "supported",
                                "reason": "Unvalidated record .get",
                                "evidence": [{"file": "src/cve_engine.py", "line": 7,
                                              "quote": "item.get("}]}]}
        code = {"src/cve_engine.py": {7: "        id = item.get('id')"}}
        result = it.validate(review, [], code)
        self.assertEqual(result["verdict"], "likely-valid")
        self.assertEqual(result["findings"][0]["status"], "supported")

    def test_http_429_is_deferred_instead_of_inaccurate_issue_judgment(self):
        issue = {"number": 146, "title": "[Integrity] Cross-session finding link",
                 "body": "src/penx_app/storage/db.py should check the link."}
        rate_limit = HTTPError("https://api.groq.com/openai/v1/chat/completions",
                               429, "rate limited", {}, None)
        with patch.object(it, "request_json", side_effect=[issue, []]), \
             patch.object(it, "model_review", side_effect=rate_limit), \
             patch.dict(it.os.environ, {"PENX_TRIAGE_GROQ_API_KEY": "fake"}):
            result = it.review("SLP-DEV1/PenX", 146, "fake", Path(__file__).resolve().parents[1])
        self.assertEqual(result["verdict"], "deferred")
        self.assertIn("automatic re-review", result["comment"].lower())
        self.assertIn("not a judgment", result["comment"])

    def test_select_oldest_pending_issue_skips_pull_requests(self):
        calls = []
        def github(url, token):
            calls.append(url)
            if "triage%3Adeferred" in url:
                return [{"number": 8, "updated_at": "2026-10-15T20:00:00Z"},
                        {"number": 7, "pull_request": {"url": "pr"},
                         "updated_at": "2026-10-14T20:00:00Z"}]
            if url.endswith("/issues/9/comments?per_page=100"):
                return [{"user": {"login": "github-actions[bot]"},
                         "body": it.MARKER + " Groq triage unavailable (HTTP 429: quota)"}]
            return [{"number": 9, "updated_at": "2026-10-15T19:00:00Z"}]
        with patch.object(it, "request_json", side_effect=github):
            self.assertEqual(it.select_pending_issue("SLP-DEV1/PenX", "fake"), 9)
        self.assertEqual(len(calls), 3)

    def test_scheduled_retry_skips_inconclusive_non_429_review(self):
        def github(url, token):
            if "/comments?" in url:
                return [{"user": {"login": "github-actions[bot]"},
                         "body": it.MARKER + " Inconclusive source evidence."}]
            if "triage%3Aunverified" in url:
                return [{"number": 90, "updated_at": "2026-10-15T18:00:00Z"}]
            return []
        with patch.object(it, "request_json", side_effect=github):
            self.assertIsNone(it.select_pending_issue("SLP-DEV1/PenX", "fake"))

    def test_historical_issue_lookup_includes_second_page(self):
        report = {"number": 200, "title": "Nmap scanner wrong port",
                  "body": "Steps to reproduce: Nmap scanner wrong port. Expected correct port."}
        first_page = [{"number": n, "title": "PR", "pull_request": {"url": "pr"}}
                      for n in range(1, 101)]
        older_issue = {"number": 42, "title": "Nmap scanner wrong port",
                       "body": "Nmap scanner wrong port", "state": "closed"}
        with patch.object(it, "request_json",
                          side_effect=[report, first_page, [older_issue]]), \
             patch.dict(it.os.environ, {"PENX_TRIAGE_GROQ_API_KEY": ""}):
            result = it.review("SLP-DEV1/PenX", 200, "fake", Path(__file__).resolve().parents[1])
        self.assertIn("/issues/42", result["comment"])


    def test_groq_413_retries_with_balanced_smaller_source(self):
        import json
        source = ("FILE src/a.py:\n" + "L1: raise ValueError\n" * 600 +
                  "\nFILE src/b.py:\n" + "L2: return result\n" * 600)
        request_prompts = []
        def fake_request(payload, token):
            request_prompts.append(json.loads(payload["messages"][1]["content"]))
            if len(request_prompts) == 1:
                raise HTTPError("https://api.groq.com/openai/v1/chat/completions",
                                413, "request too large", {}, None)
            return {"choices": [{"finish_reason": "stop", "message": {
                "content": '{"category":"bug","verdict":"unverified"}'
            }}]}
        with patch.object(it, "request_groq", side_effect=fake_request):
            result = it.model_review({"title": "Four bugs",
                                      "body": "a" * 10000},
                                     [{"number": 33, "title": "related",
                                       "body_excerpt": "b" * 1000}],
                                     source, "fake-key")
        self.assertTrue(result["_penx_compact_retry"])
        self.assertEqual(len(request_prompts), 2)
        compact = request_prompts[1]
        self.assertLessEqual(len(compact["issue_body"]), 3000)
        self.assertLessEqual(len(compact["source_excerpts"]), 11500)
        self.assertIn("FILE src/a.py:", compact["source_excerpts"])
        self.assertIn("FILE src/b.py:", compact["source_excerpts"])
        self.assertLess(len(compact["source_excerpts"]), len(source))

    def test_compact_review_can_only_cite_lines_actually_sent(self):
        indexed = {"src/a.py": {1: "raise ValueError", 2: "other"},
                   "src/b.py": {3: "return result"}}
        seen = it.verified_excerpt_lines(
            "FILE src/a.py:\nL1: raise ValueError\n"
            "FILE src/b.py:\nL3: return result", indexed)
        self.assertEqual(seen, {"src/a.py": {1: "raise ValueError"},
                                "src/b.py": {3: "return result"}})
        self.assertNotIn(2, seen.get("src/a.py", {}))


    def test_compact_context_keeps_separate_cited_bug_regions(self):
        lines = ["FILE src/scanners.py:"]
        lines.extend(f"L{n}: unrelated_line_{n}" for n in range(1, 160))
        lines.extend(f"L{n}: whatweb_logic_{n}" for n in range(200, 261))
        lines.extend(f"L{n}: katana_logic_{n}" for n in range(500, 561))
        source = "\n".join(lines)
        result = it.compact_source_excerpts(
            source, max_chars=2000,
            focus="src/scanners.py#L220-L228 src/scanners.py#L520-L528",
        )
        self.assertIn("L220: whatweb_logic_220", result)
        self.assertIn("L520: katana_logic_520", result)
        self.assertLess(len(result), len(source))

    def test_reviewer_never_requests_existing_repository_source(self):
        review = {"verdict": "needs-info",
                  "reason": "More details required",
                  "missing": ["Source code for report deletion logic",
                              "Exact Windows traceback"]}
        result = it.validate(review, [], {})
        self.assertEqual(result["missing"], ["Exact Windows traceback"])


if __name__ == "__main__":
    import unittest
    unittest.main()
