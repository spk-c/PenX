"""Architectural dependency boundaries for the modular PenX monolith.

Only inspect Python syntax; do not import optional services, access databases,
run scanners, or evaluate code from external issue reports.
"""
from __future__ import annotations

import ast
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1] / "src" / "penx_app"
PURE_DOMAIN = ROOT / "domain"
NO_DIRECT_SQL = ("analysis", "cli", "reporting")


def imports_in(module: ast.Module) -> set[str]:
    imports = set()
    for node in ast.walk(module):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module)
    return imports


class DependencyBoundaries(unittest.TestCase):
    def test_domain_does_not_depend_on_io_frameworks(self):
        blocked = ("penx_app.cli", "penx_app.storage",
                   "penx_app.reporting", "requests", "subprocess",
                   "sqlite3", "mysql", "urllib.request")
        for path in PURE_DOMAIN.rglob("*.py"):
            with self.subTest(path=path.relative_to(ROOT)):
                tree = ast.parse(path.read_text(encoding="utf-8"))
                for imported in imports_in(tree):
                    self.assertFalse(any(imported == name or imported.startswith(name + ".")
                                         for name in blocked), (path, imported))

    def test_cli_model_and_renderers_do_not_issue_sql_directly(self):
        for area in NO_DIRECT_SQL:
            for path in (ROOT / area).rglob("*.py"):
                with self.subTest(path=path.relative_to(ROOT)):
                    tree = ast.parse(path.read_text(encoding="utf-8"))
                    self.assertFalse(
                        any(isinstance(node, ast.Call) and
                            isinstance(node.func, ast.Attribute) and
                            node.func.attr in {"cursor", "executescript"}
                            for node in ast.walk(tree)),
                        f"{path} must use storage repositories, not SQL cursors",
                    )

    def test_evaluation_renderer_has_no_storage_query_execution(self):
        path = ROOT / "reporting" / "evaluation_packages.py"
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        self.assertFalse(any(isinstance(node, ast.Constant) and
                             isinstance(node.value, str) and
                             node.value.lstrip().upper().startswith(
                                 ("SELECT ", "UPDATE ", "INSERT ", "DELETE "))
                             for node in ast.walk(tree)))


if __name__ == "__main__":
    unittest.main()
