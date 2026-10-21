"""Protect GitHub Actions concurrency behavior against regressions.

No network calls and no YAML parser dependency: inspect the workflow scalars
that GitHub itself evaluates for push, pull_request and workflow_dispatch.
"""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]


def _workflow(name: str) -> str:
    return (ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8")


def _concurrency_group(workflow: str) -> str:
    block = re.search(r"(?m)^concurrency:\s*\n((?:  [^\n]*\n)+)", workflow)
    if not block:
        raise AssertionError("Missing top-level workflow concurrency")
    group = re.search(r"(?m)^  group:\s*(.+)$", block.group(1))
    if not group:
        raise AssertionError("Missing concurrency group")
    return group.group(1)


class WorkflowConcurrencyTests(unittest.TestCase):
    def test_manual_runs_cannot_cancel_tag_releases(self):
        release = _workflow("release.yml")
        group = _concurrency_group(release)
        self.assertIn("${{ github.event_name }}", group)
        self.assertIn("${{ github.ref }}", group)
        self.assertRegex(
            release, r"(?m)^  cancel-in-progress:\s*\$\{\{ github\.event_name == 'workflow_dispatch' \}\}$"
        )
        # With identical refs, workflow_dispatch and push still have different keys.
        for ref in ("refs/tags/v0.4.3", "refs/heads/main"):
            tagged = group.replace("${{ github.event_name }}", "push").replace("${{ github.ref }}", ref)
            manual = group.replace("${{ github.event_name }}", "workflow_dispatch").replace("${{ github.ref }}", ref)
            self.assertNotEqual(tagged, manual)

    def test_same_repository_push_and_pull_request_dedupe(self):
        ci = _workflow("ci.yml")
        group = _concurrency_group(ci)
        self.assertIn("${{ github.event.pull_request.head.repo.full_name || github.repository }}", group)
        self.assertIn("${{ github.head_ref || github.ref_name }}", group)
        self.assertRegex(ci, r"(?m)^  cancel-in-progress:\s*true$")
        # Resolve the two GitHub fallback expressions as they are evaluated
        # by the respective push and pull_request event contexts.
        def resolve(event_repo: str, ref_name: str, *, pr_repo: str = "",
                    head_ref: str = "") -> str:
            result = group.replace("${{ github.workflow }}", "Offline tests")
            result = result.replace(
                "${{ github.event.pull_request.head.repo.full_name || github.repository }}",
                pr_repo or event_repo,
            )
            result = result.replace("${{ github.head_ref || github.ref_name }}",
                                    head_ref or ref_name)
            return result
        self.assertEqual(
            resolve("SLP-DEV1/PenX", "feature/ci"),
            resolve("SLP-DEV1/PenX", "35/merge",
                    pr_repo="SLP-DEV1/PenX", head_ref="feature/ci"),
        )
        # Forked PRs with the same branch name must not cancel each other.
        self.assertNotEqual(
            resolve("SLP-DEV1/PenX", "35/merge",
                    pr_repo="fork-one/PenX", head_ref="patch"),
            resolve("SLP-DEV1/PenX", "36/merge",
                    pr_repo="fork-two/PenX", head_ref="patch"),
        )

    def test_pr_linux_manual_windows_and_release_integrity_remain_enabled(self):
        ci = _workflow("ci.yml")
        release = _workflow("release.yml")
        self.assertIn("python offline_tests.py", ci)
        self.assertIn("python offline_tests.py", release)
        self.assertIn("  pull_request:", ci)
        self.assertIn("name: tests (ubuntu-latest)", ci)
        self.assertIn("name: tests (windows-latest)", ci)
        self.assertIn("if: github.event_name == 'workflow_dispatch'", ci)
        self.assertIn("python scripts/build_windows.py", release)
        self.assertIn("python scripts/build_windows.py", ci)
        self.assertIn("--onedir", (ROOT / "scripts" / "build_windows.py").read_text())
        self.assertIn("z.testzip()", release)
        self.assertIn("SHA256SUMS.txt", release)
        self.assertIn("github.ref_type == 'tag'", release)


if __name__ == "__main__":
    unittest.main(verbosity=2)
