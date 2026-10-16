"""Contracts for the repository quality-coverage inventory."""
import unittest
from scripts.quality_coverage_inventory import coverage, build_report


class CoverageInventoryTests(unittest.TestCase):
    def test_gate_specific_coverage_and_package_directories(self):
        ci = (
            "python -m ruff check --select F401 src/penx_app/domain src/penx_app/cli/a.py\n"
            "python -m mypy --follow-imports=skip src/penx_app/cli/a.py\n"
        )
        modules = [
            "src/penx_app/domain/a.py",
            "src/penx_app/cli/a.py",
            "src/penx_app/cli/b.py",
        ]
        report = coverage(ci, modules)
        self.assertEqual(report["ruff_f401"], ["src/penx_app/cli/b.py"])
        self.assertEqual(report["mypy"], [
            "src/penx_app/cli/b.py", "src/penx_app/domain/a.py"
        ])

    def test_missing_gate_cannot_claim_coverage(self):
        self.assertEqual(
            coverage("", ["src/penx_app/analysis/llm.py"]),
            {"ruff_f401": ["src/penx_app/analysis/llm.py"],
             "mypy": ["src/penx_app/analysis/llm.py"]},
        )

    def test_real_inventory_has_machine_readable_counts(self):
        report = build_report()
        self.assertGreater(report["maintained_modules"], 0)
        for gate, paths in report["uncovered"].items():
            self.assertEqual(len(paths), report["uncovered_counts"][gate])


if __name__ == "__main__":
    unittest.main()
