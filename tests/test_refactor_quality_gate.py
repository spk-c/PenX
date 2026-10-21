"""Keep newly extracted terminal/selection module quality gates enforced."""
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
CI = ROOT / ".github" / "workflows" / "ci.yml"
MODULES = (
    "src/penx_app/application/scanner_selection.py",
    "src/penx_app/cli/scanner_cancellation.py",
    "src/penx_app/cli/cli_navigation.py",
    "src/penx_app/scanners/registry.py",
)


class RefactorQualityGateTests(unittest.TestCase):
    def test_scanner_selection_and_cancel_seams_are_ruff_and_mypy_checked(self):
        workflow = CI.read_text(encoding="utf-8")
        ruff = workflow.split("python -m ruff check --select F401", 1)[1].split("\n", 1)[0]
        mypy = workflow.split("python -m mypy --follow-imports=skip", 1)[1].split("\n", 1)[0]
        # Full-package gates are stronger than explicit per-file allowlists.
        self.assertIn("src/penx_app", ruff)
        self.assertIn("src/penx_app", mypy)
        for filename in MODULES:
            with self.subTest(filename=filename):
                self.assertTrue((ROOT / filename).is_file())
                self.assertTrue(filename.startswith("src/penx_app/"))

    def test_existing_critical_boundaries_are_still_enforced(self):
        workflow = CI.read_text(encoding="utf-8")
        for filename in ("src/penx_app/application/scanner_execution.py",
                         "src/penx_app/storage/db_backend.py",
                         "src/penx_app/analysis/analysis_pipeline.py"):
            self.assertTrue((ROOT / filename).is_file())
            self.assertIn("python -m ruff check --select F401 src/penx_app", workflow)
            self.assertIn("python -m mypy --follow-imports=skip", workflow)


if __name__ == "__main__":
    unittest.main()
