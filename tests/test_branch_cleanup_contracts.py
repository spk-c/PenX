"""Safety contracts for the opt-in GitHub topic-branch cleanup utility."""
from pathlib import Path
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
        self.assertIn('Dry run only; no branches deleted.', source)


if __name__ == "__main__":
    unittest.main()
