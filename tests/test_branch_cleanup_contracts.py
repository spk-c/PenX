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
        self.assertIn('if ($name -eq "main"', source)
        self.assertIn("fix|refactor|release", source)
        self.assertIn("$_.merged_at", source)
        self.assertIn("$_.head.sha -eq $branch.commit.sha", source)

    def test_rechecks_live_sha_and_open_pull_requests_before_deleting(self):
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("repos/$repo/pulls?state=open&per_page=100", source)
        self.assertIn("repos/$repo/git/ref/heads/$($candidate.Name)", source)
        self.assertIn("$current.object.sha -ne $candidate.Sha", source)
        self.assertIn("-X DELETE", source)
        self.assertIn("Write-Output -NoEnumerate $record", source)
        self.assertIn("fix|refactor|release|maintenance|docs|quality", source)
        self.assertIn("paginated", source)
        self.assertIn('Dry run only; no branches deleted.', source)


    def test_prune_workflow_is_scoped_to_explicit_merged_change(self):
        workflow = SCRIPT.parents[1] / ".github/workflows/prune-merged-branches.yml"
        source = workflow.read_text(encoding="utf-8")
        self.assertIn("branches: [main]", source)
        self.assertIn("paths:", source)
        self.assertIn("'.github/workflows/prune-merged-branches.yml'", source)
        self.assertIn("contents: write", source)
        self.assertIn("gh auth status", source)
        self.assertIn("prune_merged_github_branches.ps1 -Apply", source)
        self.assertNotIn("pull_request:", source)

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
        self.assertIn("PASS: PowerShell 5.1 JSON record enumeration", run.stdout)


if __name__ == "__main__":
    unittest.main()
