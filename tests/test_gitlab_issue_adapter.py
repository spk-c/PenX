"""Offline contracts for the opt-in GitLab triage adapter."""
import unittest
from unittest.mock import patch
from scripts import gitlab_issue_triage as adapter


class GitLabTriageTests(unittest.TestCase):
    def test_normalize_gitlab_issue_without_leaking_privileged_fields(self):
        issue = adapter._as_github_issue({
            "iid": 42, "title": "Example", "description": "Repro steps",
            "labels": ["bug"], "author": {"username": "reporter"},
        })
        self.assertEqual(issue["number"], 42)
        self.assertEqual(issue["body"], "Repro steps")
        self.assertEqual(issue["labels"], [{"name": "bug"}])
        self.assertEqual(issue["user"]["login"], "reporter")

    def test_transport_accepts_only_own_issue_lookups(self):
        def fake(path, token, **kwargs):
            self.assertEqual(token, "secret")
            self.assertEqual(path, "/issues/3")
            return {"iid": 3, "title": "Bug", "description": "", "labels": []}
        with patch.object(adapter, "api_json", side_effect=fake):
            with adapter.gitlab_review_transport("secret"):
                result = adapter.review_engine.request_json(
                    "https://api.github.com/repos/SLP-DEV1/PenX/issues/3", "secret")
                self.assertEqual(result["number"], 3)
                with self.assertRaises(ValueError):
                    adapter.review_engine.request_json(
                        "https://api.github.com/repos/other/project/issues/3", "secret")

    def test_skips_issue_already_reviewed(self):
        calls = []
        def fake(path, token, **kwargs):
            calls.append(path)
            if path.startswith("/issues?"):
                return [{"iid": 1}, {"iid": 2}]
            if path == "/issues/1/notes?per_page=100":
                return [{"body": adapter.MARKER}]
            if path == "/issues/2/notes?per_page=100":
                return []
            raise AssertionError(path)
        with patch.object(adapter, "api_json", side_effect=fake):
            self.assertEqual(adapter.choose_issue("secret"), 2)

    def test_schedule_uses_description_not_user_supplied_variables(self):
        from pathlib import Path
        ci = (Path(__file__).resolve().parents[1] / ".gitlab-ci.yml").read_text(encoding="utf-8")
        self.assertIn('CI_PIPELINE_SCHEDULE_DESCRIPTION == "PenX Daily Issue Triage"', ci)
        self.assertNotIn("PENX_RUN_ISSUE_TRIAGE", ci)

    def test_disallows_wrong_project_and_missing_token(self):
        with patch.dict(adapter.os.environ, {"CI_PROJECT_PATH": "other/penx"}, clear=True):
            with self.assertRaises(SystemExit):
                adapter.main()
        with patch.dict(adapter.os.environ, {"CI_PROJECT_PATH": adapter.PROJECT_PATH}, clear=True):
            with self.assertRaises(SystemExit):
                adapter.main()


if __name__ == "__main__":
    unittest.main(verbosity=2)
