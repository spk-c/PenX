"""Windows field evidence script is deliberately read-only and fail-closed."""
from pathlib import Path
import unittest

SCRIPT = (Path(__file__).resolve().parents[1] / "scripts"
          / "collect_refactor_field_evidence.ps1")


class FieldEvidenceScriptContracts(unittest.TestCase):
    def test_template_does_not_launch_scanners_or_installer(self):
        code = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("Get-FileHash", code)
        self.assertIn("NOT RUN", code)
        self.assertIn("NOT SIGNED OFF", code)
        self.assertIn("Test-Path -LiteralPath $file", code)
        self.assertNotIn("Start-Process", code)
        self.assertNotIn("Invoke-WebRequest", code)
        self.assertNotIn("Invoke-RestMethod", code)
        self.assertNotIn("gh api", code)
        self.assertNotIn("Remove-Item", code)


if __name__ == "__main__":
    unittest.main(verbosity=2)
