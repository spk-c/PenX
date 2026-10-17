"""Complete legacy configuration precedence matrix with isolated, offline inputs.

The key list is extracted from the production loader so new settings cannot be
introduced without falling under the same PENX_/METATRON_ precedence check.
No actual process environment, user configuration or network is modified.
"""
from __future__ import annotations

import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from penx_app.settings import load_settings
from penx_app import app_paths


SOURCE = Path(__file__).resolve().parents[1] / "src/penx_app/settings.py"
KEY_PATTERN = re.compile(r"\b(?:get|enabled|number)\('([A-Z][A-Z_]+)'")
BOOLEAN_KEYS = {"VERIFY_SOURCES", "CVE_DISCOVERY", "CVE_PRIORITY",
                "ALLOW_MODEL_WEB_SEARCH"}
NUMERIC_KEYS = {
    "CVE_MAX_SERVICES", "CVE_MAX_PACKAGES", "CVE_MAX_RESULTS",
    "CVE_MAX_VERIFY", "SCAN_INPUT_MAX_CHARS", "MAX_TOKENS",
    "TOP_K", "TIMEOUT", "MAX_LOOPS",
}


def specimen(key: str, old: bool) -> str:
    if key == "LLM_URL":
        return "http://127.0.0.1:11880" if old else "http://127.0.0.1:11881"
    if key == "STRUCTURED_OUTPUT":
        return "strict" if old else "off"
    if key == "DB_ENGINE":
        return "mariadb" if old else "sqlite"
    if key in BOOLEAN_KEYS:
        return "off" if old else "on"
    if key in NUMERIC_KEYS:
        return ("11000" if old else "12000") if key == "SCAN_INPUT_MAX_CHARS" else (
            "11" if old else "12"
        )
    return f"legacy-{key.lower()}" if old else f"current-{key.lower()}"


class SettingsMigrationMatrix(unittest.TestCase):
    def test_each_literal_loader_setting_supports_both_prefixes(self):
        # Skip the two namespace literals in source.get('PENX_' + name,
        # source.get('METATRON_' + name, ...)); those are not setting IDs.
        keys = sorted(set(KEY_PATTERN.findall(SOURCE.read_text(encoding="utf-8")))
                      - {"PENX_", "METATRON_"})
        self.assertGreaterEqual(len(keys), 25)
        with tempfile.TemporaryDirectory(prefix="penx matrix ") as folder:
            root = Path(folder)
            for key in keys:
                with self.subTest(key=key):
                    legacy = {"METATRON_" + key: specimen(key, True)}
                    primary = {"PENX_" + key: specimen(key, False)}
                    old_snapshot = dict(load_settings(root=root, env=legacy).values)
                    new_snapshot = dict(load_settings(root=root, env=primary).values)
                    both_snapshot = dict(load_settings(
                        root=root, env={**legacy, **primary}
                    ).values)
                    self.assertNotEqual(
                        old_snapshot, new_snapshot,
                        f"{key} does not change any typed setting",
                    )
                    self.assertEqual(
                        both_snapshot, new_snapshot,
                        f"PENX_{key} did not override METATRON_{key}",
                    )

    def test_process_values_override_dotenv_without_mutating_real_environment(self):
        import os
        with tempfile.TemporaryDirectory(prefix="penx unicodé ") as folder:
            root = Path(folder)
            config = root / ".env"
            config.write_text(
                "METATRON_MODEL=from-old-file\nPENX_MODEL=from-new-file\n"
                "METATRON_TIMEOUT=19\n", encoding="utf-8"
            )
            before = dict(os.environ)
            settings = load_settings(
                root=root, env={"PENX_MODEL": "from-process",
                                "PENX_TIMEOUT": "23"},
                env_file=config,
            )
            self.assertEqual(settings.MODEL_NAME, "from-process")
            self.assertEqual(settings.LLM_TIMEOUT, 23)
            self.assertEqual(dict(os.environ), before)
            self.assertEqual(sorted(p.name for p in root.iterdir()), [".env"])

    def test_portable_resolver_handles_unicode_and_read_only_program_paths(self):
        with tempfile.TemporaryDirectory(prefix="PenX portable ") as directory:
            root = Path(directory) / "Programmes é✓"
            root.mkdir()
            exe = root / "PenX.exe"
            exe.write_bytes(b"fixture (never executed)")
            with patch.object(app_paths.sys, "executable", str(exe)), \
                 patch.object(app_paths.sys, "frozen", True, create=True), \
                 patch.dict(app_paths.os.environ, {"LOCALAPPDATA": str(root / "User Data")}):
                # Without Inno's sentinel, portable mode stays next to EXE.
                self.assertEqual(app_paths.application_root(), root.resolve())
                (root / ".penx-installed").write_text("", encoding="utf-8")
                self.assertEqual(
                    app_paths.application_root(),
                    root / "User Data" / "PenX",
                )
            # Path resolution must not create the user-data folder.
            self.assertFalse((root / "User Data").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
