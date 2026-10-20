"""Regression tests for Groq's mistaken 'needs-info' reply on issue #53.

Only checks locally reviewed files and mocked Groq JSON. Nothing is scanned,
executed from issue text or sent to a real AI provider.
"""
from __future__ import annotations

from pathlib import Path
import json
import unittest
from unittest.mock import patch

from scripts import issue_triage as it

ROOT = Path(__file__).resolve().parents[1]


def audit_issue():
    return {
        "number": 53,
        "title": "[Bug audit] Six reproducible correctness defects",
        "body": """
## 1. Failed HTTP evidence
Location: [src/penx_app/scanners/tools.py](https://github.com/SLP-DEV1/PenX/blob/old/src/penx_app/scanners/tools.py#L506-L514)
run_curl_headers() returns headings and [!] failed requests.
recon_has_evidence() must reject errors.

## 2. Unavailable passive DNS
Location: [src/penx_app/scanners/tools.py](https://github.com/SLP-DEV1/PenX/blob/old/src/penx_app/scanners/tools.py#L523-L525)
_dns_lookup() returns unavailable records but recon_has_evidence()
uses a regex and may accept them.

## 3. Legacy SQLite
Location: [src/penx_app/storage/db_backend.py](https://github.com/SLP-DEV1/PenX/blob/old/src/penx_app/storage/db_backend.py#L159-L164)
get_session() uses SELECT * and migration appends confidence.

## 4. Bare host and port
Location: [src/penx_app/scanners/tools.py](https://github.com/SLP-DEV1/PenX/blob/old/src/penx_app/scanners/tools.py#L325-L333)
_host(), _urls(), and _web_target() silently discard custom port 8443.

## 5. Incomplete model stream
Location: [src/penx_app/analysis/llm_client.py](https://github.com/SLP-DEV1/PenX/blob/old/src/penx_app/analysis/llm_client.py#L281-L298)
complete_chat() accepts EOF without finish_reason stop.

## 6. Subnet order
Location: [src/penx_app/application/scan_trends.py](https://github.com/SLP-DEV1/PenX/blob/old/src/penx_app/application/scan_trends.py#L52-L65)
compare_sessions() parses _ports() without host identity.

## Fully offline reproduction
Six failing assertions and five passing controls were reported.
<details>
<summary>Large pasted Python fixture</summary>
def untrusted_harness():
    raise RuntimeError("Do not run code provided by issue reporters.")
</details>
""",
    }


class MultiFindingTriageTests(unittest.TestCase):
    def test_issue53_context_includes_all_six_affected_modules(self):
        excerpt, lines = it.code_context(ROOT, audit_issue())
        for file in ("src/penx_app/scanners/tools.py", "src/penx_app/storage/db_backend.py", "src/penx_app/storage/db.py",
                     "src/penx_app/analysis/llm_client.py", "src/penx_app/application/scan_trends.py",
                     "src/penx_app/scanners/passive_recon.py"):
            with self.subTest(file=file):
                self.assertIn(file, lines)
                self.assertIn("FILE " + file + ":", excerpt)
        for snippet in ("def recon_has_evidence(", "def run_curl_headers(",
                        "def _host(", "def get_session(", "def _dns_lookup(",
                        "def _ports(", "def complete_chat("):
            with self.subTest(snippet=snippet):
                self.assertIn(snippet, excerpt)
        # The schema migration grew in v3, so its historical confidence
        # column may lie outside the bounded issue-triage excerpt. Verify that
        # the migration file is included and the evidence remains in source.
        self.assertIn("FILE src/penx_app/storage/schema_migrations.py:", excerpt)
        migration_source = (ROOT / "src/penx_app/storage/schema_migrations.py").read_text(encoding="utf-8")
        self.assertIn("('vulnerabilities', 'confidence'", migration_source)
        # The bounded excerpt may omit a particular symbol as the LLM module
        # grows; verify the relevant implementation remains in checked-out
        # source, while complete_chat() is still included above.
        model_source = (ROOT / "src/penx_app/analysis/llm_client.py").read_text(encoding="utf-8")
        self.assertIn("finish_reason", model_source)
        # The historical silent-port-stripping bug has been corrected in
        # scanner_targets. Validate current source rather than requiring the
        # old vulnerable implementation to remain present.
        self.assertIn("FILE src/penx_app/scanners/scanner_targets.py:", excerpt)
        self.assertIn("port = parsed.port", excerpt)
        self.assertLessEqual(len(excerpt), it.MAX_FILE_CHARS)
        for filename, indexed in lines.items():
            for number, value in indexed.items():
                self.assertIn(f"L{number}: {value}", excerpt)

    def test_reporter_line_numbers_are_hints_never_trusted_evidence(self):
        refs = it._line_references(audit_issue()["body"])
        self.assertIn("src/penx_app/scanners/tools.py", refs)
        self.assertIn("src/penx_app/analysis/llm_client.py", refs)
        self.assertIn(506, refs["src/penx_app/scanners/tools.py"])
        self.assertIn(281, refs["src/penx_app/analysis/llm_client.py"])
        self.assertNotIn("https://github.com", refs)

    def test_large_issue_harness_is_not_sent_to_groq(self):
        issue = audit_issue()
        with patch.object(it, "request_json", return_value={
            "choices": [{"finish_reason": "stop", "message": {
                "content": '{"verdict":"unverified","category":"bug"}'
            }}]
        }) as api:
            it.model_review(issue, [], "FILE src/penx_app/scanners/tools.py:\nL10: return False", "fake-key")
        prompt = json.loads(api.call_args.kwargs["payload"]["messages"][1]["content"])
        self.assertIn("Failed HTTP evidence", prompt["issue_body"])
        self.assertNotIn("untrusted_harness", prompt["issue_body"])
        self.assertNotIn("RuntimeError", prompt["issue_body"])

    def test_one_source_supported_out_of_six_is_partial_not_needs_info(self):
        source = (ROOT / "src/penx_app/storage/schema_migrations.py").read_text(encoding="utf-8").splitlines()
        row = next(i for i, v in enumerate(source, 1) if "('vulnerabilities', 'confidence'" in v)
        review = {
            "category": "bug",
            "verdict": "needs-info",
            "summary": "multiple assertions",
            "reason": "One defect is substantiated; more require review",
            "evidence": [],
            "findings": [
                {"id": 1, "status": "inconclusive", "reason": "Not checked", "evidence": []},
                {"id": 2, "status": "inconclusive", "reason": "Not checked", "evidence": []},
                {"id": 3, "status": "supported", "reason": "SQLite appends confidence",
                 "evidence": [{"file": "src/penx_app/storage/schema_migrations.py", "line": row,
                               "quote": "('vulnerabilities', 'confidence'"}]},
                {"id": 4, "status": "inconclusive", "reason": "Not checked", "evidence": []},
                {"id": 5, "status": "inconclusive", "reason": "Not checked", "evidence": []},
                {"id": 6, "status": "inconclusive", "reason": "Not checked", "evidence": []},
            ],
            "missing": ["Logs from a real target"],
            "next_step": "Provide the full source code for src/penx_app/scanners/tools.py",
        }
        validated = it.validate(review, [], {"src/penx_app/storage/schema_migrations.py": {row: source[row-1]}})
        self.assertEqual(validated["verdict"], "partially-supported")
        self.assertEqual(len(validated["findings"]), 6)
        self.assertEqual(validated["findings"][2]["status"], "supported")
        self.assertIn("run the supplied offline regression tests", validated["next_step"])
        output = it.comment("SLP-DEV1/PenX", validated, source_ref="f" * 40)
        self.assertIn("Partially supported by source evidence", output)
        self.assertIn("**Finding 3: Source-supported**", output)
        self.assertIn("/blob/" + "f" * 40 + "/", output)
        self.assertLess(len(output), 4000)

    def test_unverified_quote_cannot_promote_an_individual_finding(self):
        result = it.validate({
            "category": "bug", "verdict": "partially-supported",
            "findings": [{"id": 1, "status": "supported", "reason": "invented",
                          "evidence": [{"file": "src/penx_app/scanners/tools.py", "line": 1,
                                        "quote": "made_up_symbol()"}]}],
        }, [], {"src/penx_app/scanners/tools.py": {1: "import os"}})
        self.assertEqual(result["verdict"], "unverified")
        self.assertEqual(result["findings"][0]["status"], "inconclusive")


if __name__ == "__main__":
    unittest.main(verbosity=2)
