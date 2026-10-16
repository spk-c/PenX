"""Export review package rendering is independent of SQL and scanners."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, Mock

from penx_app.reporting import evaluation_packages as render
from penx_app.storage.evaluation_repository import (
    load_evaluation_package, load_distillation_package,
)


class EvaluationPackageBoundaries(unittest.TestCase):
    def test_render_saved_evaluation_without_database_access(self):
        data = {
            "history": (7, "example.test", "2026-10-15", "active"),
            "summary": ("80/tcp open http", "AI analysis", "LOW", "fixture-model"),
            "vulns": [(3, 7, "HTTP finding", "low", "possible", "80", "http", "Evidence")],
            "fixes": [(1, 7, 3, "Apply patch", "ai")],
            "corrections": [],
            "evaluations": [],
        }
        with tempfile.TemporaryDirectory() as folder, \
             patch.object(render, "load_evaluation_package", return_value=data) as load:
            result = Path(render.export_eval_package(7, folder))
            self.assertTrue(result.is_file())
            self.assertIn("Apply patch", result.read_text(encoding="utf-8"))
            load.assert_called_once_with(7)

    def test_distillation_renders_supplied_records(self):
        fixture = {"corrections": [
            ("hallucination", "unverified banner", "HTTP finding", "medium", "example.test", "2026-10-15")
        ], "rules": []}
        with tempfile.TemporaryDirectory() as folder, \
             patch.object(render, "load_distillation_package", return_value=fixture):
            report = Path(render.export_distillation_package(folder))
            self.assertIn("unverified banner", report.read_text(encoding="utf-8"))

    def test_repository_closes_connection_on_sql_error(self):
        connection = Mock()
        connection.cursor.return_value.execute.side_effect = RuntimeError("disconnected")
        with self.assertRaises(RuntimeError):
            load_evaluation_package(1, connection_factory=lambda: connection)
        connection.close.assert_called_once_with()

    def test_distillation_connection_closes_on_error(self):
        connection = Mock()
        connection.cursor.return_value.execute.side_effect = RuntimeError("disconnected")
        with self.assertRaises(RuntimeError):
            load_distillation_package(connection_factory=lambda: connection)
        connection.close.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
