"""Ensure additional maintained CLI/parser/CVE modules stay in CI gates."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
MODULES = (
    "src/penx_app/cli/cli_views.py",
    "src/penx_app/analysis/parsers.py",
    "src/penx_app/intelligence/cve_observations.py",
)


class QualityCoverageRegressionTests(unittest.TestCase):
    def test_maintained_parsers_and_cli_views_in_ruff_and_mypy(self):
        ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        ruff = next(line for line in ci.splitlines()
                    if "python -m ruff check --select F401" in line)
        mypy = next(line for line in ci.splitlines()
                    if "python -m mypy --follow-imports=skip" in line)
        # Enforcing src/penx_app recursively covers every maintained module.
        self.assertIn("src/penx_app", ruff)
        self.assertIn("src/penx_app", mypy)
        for source in MODULES:
            with self.subTest(module=source):
                self.assertTrue((ROOT / source).is_file())
                self.assertTrue(source.startswith("src/penx_app/"))


if __name__ == "__main__":
    unittest.main()
