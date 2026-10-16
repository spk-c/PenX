"""Offline tests for the local OpenAI-compatible API including llama.cpp."""

from __future__ import annotations

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from penx_app.analysis.llm_client import (ModelConfigurationError, normalize_base_url,
                        resolve_model_name, extract_chat_text, complete_chat,
                        fetch_models)


class FakeLlamaServer(BaseHTTPRequestHandler):
    model_ids = ["penx-gguf"]
    seen = []

    def reply(self, status, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.seen.append(("GET", self.path, None, self.headers.get("Authorization")))
        if self.path == "/v1/models":
            return self.reply(200, {"object": "list", "data": [{"id": x} for x in self.model_ids]})
        self.reply(404, {"error": "Not found"})

    def do_POST(self):
        payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self.seen.append(("POST", self.path, payload, self.headers.get("Authorization")))
        if self.path == "/v1/chat/completions":
            return self.reply(200, {"choices": [{"message": {"role": "assistant", "content": "Local GGUF response"}}]})
        self.reply(404, {"error": "Not found"})

    def log_message(self, *_):
        return


class LlamaCppTests(unittest.TestCase):
    def test_endpoint_formats(self):
        for inp in ("http://localhost:8080", "http://localhost:8080/v1", "http://localhost:8080/v1/chat/completions/"):
            self.assertEqual(normalize_base_url(inp), "http://localhost:8080")
        self.assertEqual(normalize_base_url("http://127.0.0.1:9931/custom/v1"), "http://127.0.0.1:9931/custom")
        with self.assertRaises(ValueError):
            normalize_base_url("localhost:8080")
        with self.assertRaises(ValueError):
            normalize_base_url("http://localhost:8080/?x=1")

    def test_explicit_model_no_discovery(self):
        with patch("penx_app.analysis.llm_client.fetch_models", side_effect=AssertionError("Unexpected GET")):
            self.assertEqual(resolve_model_name("custom-alias", "http://localhost/v1/models"), "custom-alias")
        with self.assertRaises(ModelConfigurationError):
            resolve_model_name("your-local-model", "http://localhost/v1/models")

    def test_auto_errors(self):
        with patch("penx_app.analysis.llm_client.fetch_models", return_value=[]):
            with self.assertRaisesRegex(ModelConfigurationError, "No models"):
                resolve_model_name("auto", "http://localhost/v1/models")
        with patch("penx_app.analysis.llm_client.fetch_models", return_value=["first", "second"]):
            with self.assertRaisesRegex(ModelConfigurationError, "Multiple models"):
                resolve_model_name("AUTO", "http://localhost/v1/models")

    def test_reasoning_and_parts(self):
        # Never treat reasoning-only output as a completed assessment.
        self.assertEqual(extract_chat_text({"choices": [{"message": {"content": None, "reasoning_content": "Private thinking"}}]}), "")
        self.assertEqual(extract_chat_text({"choices": [{"message": {"content": [{"type": "text", "text": "Part A"}, {"type": "text", "text": "Part B"}]}}]}), "Part A\nPart B")

    def test_local_llama_cpp_compatible_server(self):
        FakeLlamaServer.seen = []
        FakeLlamaServer.model_ids = ["my-local-gguf"]
        server = ThreadingHTTPServer(("127.0.0.1", 0), FakeLlamaServer)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            base = f"http://127.0.0.1:{server.server_port}"
            result = complete_chat([{"role": "user", "content": "Hello"}],
                                   url=base + "/v1/chat/completions",
                                   models_url=base + "/v1/models",
                                   model_name="auto", api_key="test-key",
                                   max_tokens=99, top_k=16, temperature=0.2)
            self.assertEqual(result, ("my-local-gguf", "Local GGUF response"))
            self.assertEqual([x[0] for x in FakeLlamaServer.seen], ["GET", "POST"])
            self.assertEqual(FakeLlamaServer.seen[1][2]["model"], "my-local-gguf")
            self.assertEqual(FakeLlamaServer.seen[1][2]["max_tokens"], 99)
            self.assertEqual(FakeLlamaServer.seen[1][2]["top_k"], 16)
            self.assertEqual(FakeLlamaServer.seen[1][3], "Bearer test-key")
            self.assertEqual(fetch_models(base + "/v1/models"), ["my-local-gguf"])
            FakeLlamaServer.seen.clear()
            complete_chat([{"role": "user", "content": "Hi"}],
                          url=base + "/v1/chat/completions", models_url=base + "/v1/models",
                          model_name="manual-alias")
            self.assertEqual([x[0] for x in FakeLlamaServer.seen], ["POST"])
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
