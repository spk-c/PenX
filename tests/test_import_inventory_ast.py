"""Regression checks for the legacy import-inventory AST scanner."""
import tempfile
import unittest
from pathlib import Path
from scripts import import_inventory


class LegacyImportReferenceTests(unittest.TestCase):
    def _scan(self, source: str) -> dict[str, int]:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "consumer.py"
            path.write_text(source, encoding="utf-8")
            return import_inventory.string_refs(path)

    def test_patch_object_string_target_is_not_counted(self):
        self.assertEqual(
            self._scan('from unittest.mock import patch\npatch.object("tools.method", "name")\n'),
            {},
        )

    def test_patch_dotted_target_still_counted(self):
        self.assertEqual(
            self._scan('from unittest.mock import patch\npatch("tools.run_tool")\n'),
            {"tools": 1},
        )

    def test_dynamic_import_still_counted(self):
        self.assertEqual(
            self._scan('import importlib\nimportlib.import_module("tools")\n'),
            {"tools": 1},
        )

    def test_non_reference_string_not_counted(self):
        self.assertEqual(
            self._scan('print("tools.run_tool")\n'),
            {},
        )


if __name__ == "__main__":
    unittest.main()
