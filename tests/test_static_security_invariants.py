"""Offline static checks for dangerous command execution in PenX application code.

This is a focused guard, not a complete security scan or taint analysis.
"""
from __future__ import annotations

import ast
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class StaticSecurityTests(unittest.TestCase):
    def test_no_shell_true_or_string_shell_execution(self):
        paths = [ROOT / "penx.py", *sorted((ROOT / "src").rglob("*.py")),
                 *sorted((ROOT / "scripts").glob("*.py")),
                 ROOT / "install_scanners_windows.py",
                 ROOT / "windows_python_setup.py"]
        violations = []
        for path in paths:
            if not path.is_file():
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                func = node.func
                dotted = (
                    f"{func.value.id}.{func.attr}"
                    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name)
                    else func.id if isinstance(func, ast.Name) else ""
                )
                if dotted in ("os.system", "os.popen", "subprocess.getoutput",
                              "subprocess.getstatusoutput"):
                    violations.append(f"{path.name}:{node.lineno}: {dotted}")
                # subprocess APIs already default to shell=False. Explicit
                # shell= expressions must be literal False; leaving it out is safe.
                if dotted in ("subprocess.run", "subprocess.Popen", "subprocess.call",
                              "subprocess.check_call", "subprocess.check_output"):
                    for keyword in node.keywords:
                        if keyword.arg == "shell" and not (
                            isinstance(keyword.value, ast.Constant) and
                            keyword.value.value is False
                        ):
                            violations.append(f"{path.name}:{node.lineno}: shell not explicitly False")
        self.assertEqual(violations, [])


if __name__ == "__main__":
    unittest.main()
