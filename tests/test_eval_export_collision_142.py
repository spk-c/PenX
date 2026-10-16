"""Same-second evaluator/distillation exports must not overwrite earlier results."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from penx_app.reporting import evaluation_packages


class PackageExportCollisionTests(unittest.TestCase):
    def test_same_second_eval_export_is_exclusive(self):
        payload = {
            "history": (3, "example.test", "today", "active"),
            "summary": ("offline scan", "model analysis", "LOW", "fixture"),
            "vulns": [], "fixes": [], "corrections": [], "evaluations": [],
        }
        with tempfile.TemporaryDirectory() as folder, \
             patch.object(evaluation_packages, "load_evaluation_package", return_value=payload), \
             patch.object(evaluation_packages, "datetime") as date:
            date.now.return_value.strftime.return_value = "20261015_123456"
            first = Path(evaluation_packages.export_eval_package(3, folder))
            first_content = first.read_text(encoding="utf-8")
            second = Path(evaluation_packages.export_eval_package(3, folder))
            self.assertNotEqual(first, second)
            self.assertEqual(first.read_text(encoding="utf-8"), first_content)
            self.assertTrue(second.is_file())

    def test_same_second_distillation_export_is_exclusive(self):
        payload = {
            "corrections": [("verified", "reviewed", "sample", "low", "example.test", "now")],
            "rules": [],
        }
        with tempfile.TemporaryDirectory() as folder, \
             patch.object(evaluation_packages, "load_distillation_package", return_value=payload), \
             patch.object(evaluation_packages, "datetime") as date:
            date.now.return_value.strftime.return_value = "20261015_123456"
            first = Path(evaluation_packages.export_distillation_package(folder))
            contents = first.read_text(encoding="utf-8")
            second = Path(evaluation_packages.export_distillation_package(folder))
            self.assertNotEqual(first, second)
            self.assertEqual(first.read_text(encoding="utf-8"), contents)
            self.assertTrue(second.is_file())


if __name__ == "__main__":
    unittest.main()
