"""Exhaustive, offline precedence contracts for all current Settings keys.

These are non-destructive snapshots with an empty process environment mapping.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from penx_app.settings import load_settings


# Legacy suffix -> immutable Settings attribute, valid old value, valid new value.
CASES = (
    ("LLM_URL", "LLM_BASE_URL", "http://localhost:4234", "http://localhost:8234"),
    ("MODEL", "MODEL_NAME", "legacy-model", "new-model"),
    ("LLM_API_KEY", "LLM_API_KEY", "legacy-secret", "new-secret"),
    ("STRUCTURED_OUTPUT", "STRUCTURED_MODE", "off", "strict"),
    ("VERIFY_SOURCES", "VERIFY_SOURCES", "off", "on"),
    ("NVD_API_KEY", "NVD_API_KEY", "legacy-nvd", "new-nvd"),
    ("CVE_DISCOVERY", "CVE_DISCOVERY", "off", "on"),
    ("CVE_MAX_SERVICES", "CVE_MAX_SERVICES", "1", "2"),
    ("CVE_MAX_PACKAGES", "CVE_MAX_PACKAGES", "2", "3"),
    ("CVE_MAX_RESULTS", "CVE_MAX_RESULTS", "4", "5"),
    ("GITHUB_ADVISORY_TOKEN", "GITHUB_ADVISORY_TOKEN", "old-token", "new-token"),
    ("CVE_PRIORITY", "CVE_PRIORITY", "off", "on"),
    ("CVE_DISTRO_HINT", "CVE_DISTRO_HINT", "DEBIAN", "UBUNTU"),
    ("CVE_MAX_VERIFY", "CVE_MAX_VERIFY", "5", "7"),
    ("PACKAGE_INVENTORY", "PACKAGE_INVENTORY", "old.json", "new.json"),
    ("DEBIAN_TRACKER_JSON", "DEBIAN_TRACKER_JSON", "old.json", "new.json"),
    ("SCAN_INPUT_MAX_CHARS", "SCAN_INPUT_MAX_CHARS", "3000", "6000"),
    ("MAX_TOKENS", "MAX_TOKENS", "1234", "4321"),
    ("TOP_K", "TOP_K", "3", "4"),
    ("TIMEOUT", "LLM_TIMEOUT", "12", "24"),
    ("MAX_LOOPS", "MAX_TOOL_LOOPS", "2", "3"),
    ("DB_HOST", "DB_HOST", "old-host", "new-host"),
    ("DB_USER", "DB_USER", "old-user", "new-user"),
    ("DB_PASS", "DB_PASSWORD", "old-pass", "new-pass"),
    ("DB_NAME", "DB_NAME", "old-db", "new-db"),
    ("DB_ENGINE", "DB_ENGINE", "sqlite", "mariadb"),
    ("DB_PATH", "DB_PATH", "old.db", "new.db"),
    ("NMAP_PATH", "NMAP_PATH", "old-nmap", "new-nmap"),
    ("NIKTO_PATH", "NIKTO_PATH", "old-nikto", "new-nikto"),
    ("WHATWEB_PATH", "WHATWEB_PATH", "old-whatweb", "new-whatweb"),
)


class LegacySettingsMatrixTests(unittest.TestCase):
    def test_every_configured_field_supports_legacy_and_new_precedence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for suffix, attr, old, new in CASES:
                with self.subTest(suffix=suffix):
                    legacy = load_settings(
                        root=root, env={"METATRON_" + suffix: old},
                    )
                    new_only = load_settings(
                        root=root, env={"PENX_" + suffix: new},
                    )
                    both = load_settings(
                        root=root, env={"METATRON_" + suffix: old,
                                        "PENX_" + suffix: new},
                    )
                    self.assertEqual(getattr(both, attr),
                                     getattr(new_only, attr))
                    self.assertNotEqual(getattr(legacy, attr),
                                        getattr(new_only, attr))
            self.assertEqual(list(root.iterdir()), [])

    def test_zero_side_effects_for_read_only_empty_installation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "read only install"
            root.mkdir()
            snapshot = load_settings(root=root, env={"PENX_MODEL": "fixture"})
            self.assertEqual(snapshot.MODEL_NAME, "fixture")
            self.assertFalse((root / "data").exists())
            self.assertFalse((root / ".env").exists())

    def test_empty_new_name_does_not_fall_back_to_old_secret(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = load_settings(root=Path(directory), env={
                "METATRON_LLM_API_KEY": "old-secret",
                "PENX_LLM_API_KEY": "",
            })
            self.assertEqual(settings.LLM_API_KEY, "")


if __name__ == "__main__":
    unittest.main(verbosity=2)
