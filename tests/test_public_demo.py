"""The public demo must generate actual PenX-format reports from synthetic data."""
from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class PublicDemoTests(unittest.TestCase):
    def test_synthetic_reports_are_generated_without_real_scans(self):
        with tempfile.TemporaryDirectory(prefix="penx_public_demo_") as tmp:
            result = subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "generate_demo_report.py"),
                 "--output-dir", tmp],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            html = Path(tmp) / "penx_SL1_example_test.html"
            pdf = Path(tmp) / "penx_SL1_example_test.pdf"
            self.assertTrue(html.is_file())
            self.assertTrue(pdf.is_file())
            report = html.read_text(encoding="utf-8")
            self.assertIn("example.test", report)
            self.assertIn("SYNTHETIC DEMO", report)
            self.assertIn("Illustrative HTTP header review", report)
            self.assertTrue(pdf.read_bytes().startswith(b"%PDF"))
            self.assertIn("Synthetic report only", result.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
