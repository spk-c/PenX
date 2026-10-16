"""Offline regression coverage for first-run local AI terminal setup."""
from __future__ import annotations

import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from dotenv import dotenv_values
import requests

from penx_app.setup import llm_setup


class LlmSetupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.root.joinpath(".env.example").write_text(
            "# A retained comment\n"
            "PENX_LLM_URL=http://127.0.0.1:1234\n"
            "PENX_MODEL=your-local-model\n"
            "PENX_DB_ENGINE=sqlite\n"
            "# PENX_SHODAN_API_KEY=\n", encoding="utf-8",
        )
        # No real service or user key should ever be used in these tests.
        excluded = {"PENX_LLM_URL", "PENX_MODEL", "PENX_LLM_API_KEY",
                    "METATRON_LLM_URL", "METATRON_MODEL", "METATRON_LLM_API_KEY"}
        self.env = patch.dict(os.environ,
                              {k: v for k, v in os.environ.items() if k not in excluded},
                              clear=True)
        self.env.start()
        self.addCleanup(self.env.stop)

    def test_missing_env_and_placeholder_start_wizard(self):
        self.assertTrue(llm_setup.needs_setup(self.root))
        self.root.joinpath(".env").write_text(
            "PENX_LLM_URL=http://localhost:8080\nPENX_MODEL=your-local-model\n",
            encoding="utf-8")
        self.assertTrue(llm_setup.needs_setup(self.root))

    def test_existing_valid_config_is_not_prompted_or_changed(self):
        file = self.root / ".env"
        file.write_text("PENX_LLM_URL=http://127.0.0.1:8080\nPENX_MODEL=gguf-prod\n",
                        encoding="utf-8")
        with patch("builtins.input", side_effect=AssertionError("Must not prompt")):
            self.assertFalse(llm_setup.maybe_configure_llm(self.root, interactive=True))
        self.assertEqual(file.read_text(encoding="utf-8").splitlines()[-1],
                         "PENX_MODEL=gguf-prod")

    def test_noninteractive_source_does_not_block(self):
        with patch("builtins.input", side_effect=AssertionError("Must not prompt")):
            self.assertFalse(llm_setup.maybe_configure_llm(self.root, interactive=False))
        self.assertFalse((self.root / ".env").exists())

    def test_guided_ollama_selection_with_model_list_and_live_test(self):
        # Backend, accept URL, no auth, model #2, test yes, save yes.
        replies = iter(["2", "", "n", "2", "y", "y"])
        with patch("builtins.input", side_effect=lambda *_: next(replies)), \
             patch("penx_app.setup.llm_setup.fetch_models", return_value=["wrong", "my-ollama"]), \
             patch("penx_app.setup.llm_setup.complete_chat", return_value=("my-ollama", "OK")) as complete, \
             patch("sys.stdout", new_callable=io.StringIO) as output:
            self.assertTrue(llm_setup.maybe_configure_llm(self.root, interactive=True))
        data = dotenv_values(self.root / ".env")
        self.assertEqual(data["PENX_LLM_URL"], "http://127.0.0.1:11434")
        self.assertEqual(data["PENX_MODEL"], "my-ollama")
        self.assertEqual(data["PENX_LLM_API_KEY"], "")
        self.assertEqual(data["PENX_DB_ENGINE"], "sqlite")
        self.assertIn("# A retained comment", (self.root / ".env").read_text(encoding="utf-8"))
        self.assertIn("[OK] AI responded", output.getvalue())
        self.assertEqual(complete.call_args.kwargs["max_tokens"], 24)

    def test_api_key_getpass_hidden_preserves_special_characters(self):
        replies = iter(["3", "", "y", "1", "n", "y", "y"])
        secret = 'hidden-$abc#abc\\word'
        with patch("builtins.input", side_effect=lambda *_: next(replies)), \
             patch("penx_app.setup.llm_setup.getpass.getpass", return_value=secret) as secret_input, \
             patch("penx_app.setup.llm_setup.fetch_models", return_value=["secure-model"]) as list_models, \
             patch("sys.stdout", new_callable=io.StringIO) as output:
            self.assertTrue(llm_setup.maybe_configure_llm(self.root, interactive=True))
        self.assertEqual(secret_input.call_count, 1)
        self.assertEqual(list_models.call_args.kwargs["api_key"], secret)
        self.assertEqual(dotenv_values(self.root / ".env")["PENX_LLM_API_KEY"], secret)
        self.assertNotIn(secret, output.getvalue())

    def test_failed_llm_handshake_requires_explicit_override_to_save(self):
        replies = iter(["1", "", "n", "1", "y", "n", "n"])
        err = requests.exceptions.ConnectionError("offline")
        with patch("builtins.input", side_effect=lambda *_: next(replies)), \
             patch("penx_app.setup.llm_setup.fetch_models", return_value=["model"]), \
             patch("penx_app.setup.llm_setup.complete_chat", side_effect=err):
            self.assertFalse(llm_setup.maybe_configure_llm(self.root, interactive=True))
        self.assertFalse((self.root / ".env").exists())

    def test_manual_model_works_when_model_registry_unavailable(self):
        replies = iter(["4", "", "n", "manual-gguf", "n", "y", "y"])
        with patch("builtins.input", side_effect=lambda *_: next(replies)), \
             patch("penx_app.setup.llm_setup.fetch_models", side_effect=requests.exceptions.ConnectionError):
            self.assertTrue(llm_setup.maybe_configure_llm(self.root, interactive=True))
        self.assertEqual(dotenv_values(self.root / ".env")["PENX_MODEL"], "manual-gguf")

    def test_force_wizard_preserves_unrelated_keys_and_removes_duplicates(self):
        file = self.root / ".env"
        file.write_text(
            "PENX_DB_ENGINE=sqlite\n"
            "PENX_LLM_URL=http://localhost:1111\n"
            "PENX_MODEL=old\nPENX_MODEL=overridden\n"
            "PENX_SHODAN_INTERNETDB=off\n", encoding="utf-8")
        llm_setup.save_settings(self.root, url="http://localhost:8080",
                                model="current", api_key="new#secret")
        content = file.read_text(encoding="utf-8")
        self.assertEqual(content.count("PENX_MODEL="), 1)
        self.assertIn("PENX_DB_ENGINE=sqlite", content)
        self.assertIn("PENX_SHODAN_INTERNETDB=off", content)
        self.assertEqual(dotenv_values(file)["PENX_LLM_API_KEY"], "new#secret")

    def test_invalid_url_rejected(self):
        for url in ("not-an-url", "http://user:password@localhost:8080",
                    "http://localhost:8080/?bad=1", "file:///etc/passwd"):
            with self.assertRaises(ValueError):
                llm_setup._url(url)

    def test_cancel_keeps_original_env_untouched(self):
        file = self.root / ".env"
        file.write_text("PENX_DB_ENGINE=mariadb\n", encoding="utf-8")
        with patch("builtins.input", return_value="q"):
            self.assertFalse(llm_setup.maybe_configure_llm(self.root, interactive=True))
        self.assertEqual(file.read_text(encoding="utf-8"), "PENX_DB_ENGINE=mariadb\n")

    def test_process_configurations_respected(self):
        with patch.dict(os.environ, {
            "PENX_LLM_URL": "http://127.0.0.1:1234",
            "PENX_MODEL": "env-model",
        }):
            self.assertFalse(llm_setup.needs_setup(self.root))


if __name__ == "__main__":
    unittest.main(verbosity=2)
