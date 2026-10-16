"""Legacy METATRON_* settings keep working at every configuration boundary.

The ``METATRON_`` prefix is the pre-rename environment namespace. The
``PENX_`` key always wins when both are present; this suite pins the
fallback at the boundaries that still honor the legacy name:

- ``settings.load_settings`` (all typed settings)
- ``config.setting`` (legacy environment accessor)
- ``setup.first_run_setup`` (import-time scanner path capture)
- ``scanners.scanner_runtime.find_runtime`` (ruby/perl lookup)

``setup.llm_setup.effective_settings`` is already pinned by
``test_llm_setup``; ``test_refactor_contracts`` covers the
``PENX_``-wins precedence for model/database keys.
"""
from __future__ import annotations

import importlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from penx_app import config
from penx_app.scanners import scanner_runtime
from penx_app.settings import load_settings


def _env_without(*names: str) -> dict:
    return {key: value for key, value in os.environ.items() if key not in names}


class LegacySettingsFallbackContracts(unittest.TestCase):
    def test_load_settings_falls_back_to_legacy_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = load_settings(root=Path(directory), env={
                'METATRON_MAX_TOKENS': '1234',
                'METATRON_VERIFY_SOURCES': 'off',
                'METATRON_NVD_API_KEY': 'legacy-key',
                'METATRON_TIMEOUT': '77',
            })
            self.assertEqual(settings.MAX_TOKENS, 1234)
            self.assertFalse(settings.VERIFY_SOURCES)
            self.assertEqual(settings.NVD_API_KEY, 'legacy-key')
            self.assertEqual(settings.LLM_TIMEOUT, 77)

    def test_config_setting_honors_legacy_process_env(self):
        base = _env_without('PENX_LLM_TIMEOUT', 'METATRON_LLM_TIMEOUT')
        with patch.dict(os.environ, {**base, 'METATRON_LLM_TIMEOUT': '77'}, clear=True):
            self.assertEqual(config.setting('LLM_TIMEOUT', '60'), '77')
        with patch.dict(os.environ,
                        {**base, 'PENX_LLM_TIMEOUT': '78', 'METATRON_LLM_TIMEOUT': '77'},
                        clear=True):
            self.assertEqual(config.setting('LLM_TIMEOUT', '60'), '78')
        with patch.dict(os.environ, base, clear=True):
            self.assertEqual(config.setting('LLM_TIMEOUT', '60'), '60')

    def test_first_run_path_capture_honors_legacy_env(self):
        from penx_app.setup import first_run_setup
        keys = ('PENX_NMAP_PATH', 'METATRON_NMAP_PATH',
                'PENX_NIKTO_PATH', 'METATRON_NIKTO_PATH',
                'PENX_WHATWEB_PATH', 'METATRON_WHATWEB_PATH')
        base = _env_without(*keys)
        try:
            with patch.dict(os.environ, {**base, 'METATRON_NMAP_PATH': 'legacy-nmap'},
                            clear=True):
                importlib.reload(first_run_setup)
            # The import-time capture must have picked up the legacy key.
            self.assertEqual(first_run_setup.NMAP_PATH, 'legacy-nmap')
            self.assertEqual(first_run_setup._path_setting('NIKTO_PATH', ''), '')
        finally:
            with patch.dict(os.environ, base, clear=True):
                importlib.reload(first_run_setup)

    def test_runtime_lookup_honors_legacy_path_override(self):
        with tempfile.TemporaryDirectory() as directory:
            ruby = Path(directory) / 'ruby.exe'
            ruby.write_bytes(b'')
            base = _env_without('PENX_RUBY_PATH', 'METATRON_RUBY_PATH',
                                'PENX_PERL_PATH', 'METATRON_PERL_PATH')
            with patch.dict(os.environ, {**base, 'METATRON_RUBY_PATH': str(ruby)},
                            clear=True):
                self.assertEqual(scanner_runtime.find_runtime('ruby'),
                                 str(ruby.resolve()))
            with patch.dict(os.environ, {**base, 'METATRON_PERL_PATH': str(ruby)},
                            clear=True):
                self.assertEqual(scanner_runtime.find_runtime('perl'),
                                 str(ruby.resolve()))
            # The PENX_ key wins per value over the legacy key.
            with patch.dict(os.environ,
                            {**base, 'PENX_RUBY_PATH': str(ruby),
                             'METATRON_RUBY_PATH': 'bogus'}, clear=True):
                self.assertEqual(scanner_runtime.find_runtime('ruby'),
                                 str(ruby.resolve()))
            with patch.dict(os.environ, base, clear=True):
                self.assertNotEqual(scanner_runtime.find_runtime('ruby'),
                                    str(ruby.resolve()))


if __name__ == "__main__":
    unittest.main()
