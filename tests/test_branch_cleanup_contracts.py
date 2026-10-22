"""Safety contracts for the opt-in GitHub topic-branch cleanup utility."""
from pathlib import Path
import subprocess
import sys
import unittest

SCRIPT = (Path(__file__).resolve().parents[1] /
          "scripts/prune_merged_github_branches.ps1")


class BranchCleanupContracts(unittest.TestCase):
    def test_default_dry_run_and_narrow_ref_scope(self):
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("param([switch]$Apply)", source)
        self.assertIn('if (-not $Apply)', source)
        self.assertIn("if ($name -eq $main", source)
        self.assertIn("chore|docs|feat|feature|fix|maintenance|quality|refactor|release", source)
        self.assertIn("$_.merged_at", source)
        self.assertIn("$_.head.sha -ceq $b.commit.sha", source)

    def test_rechecks_live_sha_and_open_pull_requests_before_deleting(self):
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('Get-GhPages "repos/$repo/pulls?state=open"', source)
        self.assertIn("repos/$repo/branches/$encoded", source)
        self.assertIn("$current.commit.sha -cne $candidate.Sha", source)
        self.assertIn("-X DELETE", source)
        self.assertIn("Get-GhPages", source)
        self.assertIn("Get-Comparison", source)
        self.assertIn('compare/$main...$encoded', source)
        self.assertNotIn('compare/$encoded...$main', source)
        self.assertIn("Pagination limit reached", source)
        self.assertIn('Dry run only; no branches deleted.', source)


    def test_branch_pruning_remains_opt_in_without_privileged_workflow(self):
        workflows = SCRIPT.parents[1] / ".github" / "workflows"
        self.assertFalse((workflows / "prune-merged-branches.yml").exists())
        for workflow in workflows.glob("*.yml"):
            with self.subTest(workflow=workflow.name):
                self.assertNotIn(
                    "prune_merged_github_branches.ps1 -Apply",
                    workflow.read_text(encoding="utf-8"),
                )

    @unittest.skipUnless(sys.platform == "win32", "Windows PowerShell 5.1 only")
    def test_windows_powershell_uses_individual_mocked_gh_json_records(self):
        fixture = SCRIPT.parents[1] / "tests/powershell/test_prune_merged_branches.ps1"
        run = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive",
             "-ExecutionPolicy", "Bypass", "-File", str(fixture)],
            capture_output=True, text=True, timeout=45, check=False,
            cwd=SCRIPT.parents[1],
        )
        self.assertEqual(run.returncode, 0, run.stdout + "\n" + run.stderr)
        self.assertIn("PASS: PowerShell 5.1 mocked merged/ancestor proof", run.stdout)


if __name__ == "__main__":
    unittest.main()
