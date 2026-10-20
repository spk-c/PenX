"""Offline compatibility tests for heterogeneous local OpenAI-style backends."""
from __future__ import annotations

import unittest
from unittest.mock import MagicMock, Mock, patch

import requests

from penx_app.analysis.llm_client import complete_chat, probe_model_capabilities
from penx_app.setup.llm_setup import discover_local_backends, _DISCOVERY_ENDPOINTS


CHAT = "http://127.0.0.1:8080/v1/chat/completions"
MODELS = "http://127.0.0.1:8080/v1/models"
MESSAGES = [{"role": "user", "content": "Offline fixture only."}]


def good_response(message="OK", *, stream=False):
    response = MagicMock() if stream else Mock()
    response.raise_for_status.return_value = None
    response.json.return_value = {"choices": [{
        "finish_reason": "stop", "message": {"content": message}
    }]}
    if stream:
        response.headers = {"content-type": "application/json"}
        response.__enter__.return_value = response
    return response


def error_response(status, message):
    response = Mock()
    response.status_code = status
    response.json.return_value = {"error": {"message": message}}
    response.raise_for_status.side_effect = requests.HTTPError(
        "Hidden upstream message", response=response)
    return response


class SamplerNegotiationTests(unittest.TestCase):
    def invoke(self, post, **kwargs):
        with patch("penx_app.analysis.llm_client.requests.post",
                   side_effect=AssertionError("No real HTTP allowed")), \
             patch("penx_app.analysis.llm_client.requests.get",
                   side_effect=AssertionError("No real discovery allowed")):
            return complete_chat(
                MESSAGES, url=CHAT, models_url=MODELS, model_name="fixture",
                http_post=post, **kwargs)

    def test_unsupported_top_k_retries_once_without_it(self):
        bad = error_response(400, "Unrecognized request argument supplied: top_k")
        good = good_response("Accepted")
        post = Mock(side_effect=[bad, good])
        self.assertEqual(self.invoke(post), ("fixture", "Accepted"))
        self.assertEqual(post.call_count, 2)
        self.assertIn("top_k", post.call_args_list[0].kwargs["json"])
        self.assertNotIn("top_k", post.call_args_list[1].kwargs["json"])
        bad.close.assert_called_once()
        good.close.assert_called_once()

    def test_pydantic_style_422_extra_input_is_recognized(self):
        bad = error_response(422, "top_k: Extra inputs are not permitted")
        post = Mock(side_effect=[bad, good_response()])
        self.assertEqual(self.invoke(post)[1], "OK")
        self.assertEqual(post.call_count, 2)

    def test_streaming_retries_before_emitting_any_content(self):
        bad = error_response(400, "Unknown parameter 'top_k'")
        good = good_response("Stream JSON fallback", stream=True)
        post = Mock(side_effect=[bad, good])
        deltas = []
        self.assertEqual(self.invoke(post, stream_callback=deltas.append)[1],
                         "Stream JSON fallback")
        self.assertEqual(deltas, ["Stream JSON fallback"])
        self.assertTrue(post.call_args_list[0].kwargs["stream"])
        self.assertTrue(post.call_args_list[1].kwargs["stream"])
        self.assertNotIn("top_k", post.call_args_list[1].kwargs["json"])
        bad.close.assert_called_once()

    def test_unrelated_error_never_downgrades_request(self):
        for code, message in (
            (401, "Unrecognized request argument supplied: top_k"),
            (400, "context exhausted"),
            (500, "Unknown parameter top_k"),
            (422, "top_k must be >= 1"),
        ):
            with self.subTest(code=code, message=message):
                post = Mock(return_value=error_response(code, message))
                with self.assertRaises(requests.HTTPError):
                    self.invoke(post)
                post.assert_called_once()

    def test_second_failure_propagates_and_closes_both_responses(self):
        first = error_response(400, "Unknown parameter top_k")
        second = error_response(400, "model not found")
        post = Mock(side_effect=[first, second])
        with self.assertRaises(requests.HTTPError):
            self.invoke(post)
        self.assertEqual(post.call_count, 2)
        first.close.assert_called_once()
        second.close.assert_called_once()

    def test_timeout_is_not_retried(self):
        post = Mock(side_effect=requests.Timeout("offline"))
        with self.assertRaises(requests.Timeout):
            self.invoke(post)
        post.assert_called_once()


class CapabilityChecksTests(unittest.TestCase):
    def probe(self, chat):
        with patch("penx_app.analysis.llm_client.requests.post",
                   side_effect=AssertionError("No network")):
            return probe_model_capabilities(
                url=CHAT, models_url=MODELS, model_name="fixture",
                chat=chat)

    def test_successful_checks_validate_content(self):
        calls = []
        def ask(messages, **kwargs):
            calls.append(kwargs)
            if "stream_callback" in kwargs:
                kwargs["stream_callback"]("OK")
                return "fixture", "OK"
            if "response_format" in kwargs:
                return "fixture", '{"ok":true}'
            return "fixture", "OK"
        self.assertEqual(self.probe(ask), {
            "chat": True, "streaming": True,
            "json_schema": True, "json_object": True,
        })
        self.assertEqual(len(calls), 4)
        self.assertEqual(calls[2]["response_format"]["type"], "json_schema")

    def test_schema_fails_and_json_object_passes(self):
        def ask(messages, **kwargs):
            if kwargs.get("response_format", {}).get("type") == "json_schema":
                raise requests.HTTPError("synthetic unsupported schema")
            if kwargs.get("response_format"):
                return "fixture", '{"ok":true}'
            return "fixture", "OK"
        self.assertEqual(self.probe(ask), {
            "chat": True, "streaming": True,
            "json_schema": False, "json_object": True,
        })

    def test_invalid_json_never_counts_as_support(self):
        def ask(messages, **kwargs):
            return "fixture", "Not JSON"
        self.assertEqual(self.probe(ask), {
            "chat": True, "streaming": True,
            "json_schema": False, "json_object": False,
        })

    def test_no_chat_exits_early_without_more_requests(self):
        ask = Mock(side_effect=requests.ConnectionError("offline"))
        self.assertEqual(self.probe(ask), {
            "chat": False, "streaming": False,
            "json_schema": False, "json_object": False,
        })
        ask.assert_called_once()


class LocalDiscoveryTests(unittest.TestCase):
    def test_fixed_localhost_endpoints_only(self):
        queried = []
        def lookup(url, timeout):
            queried.append((url, timeout))
            return ["fixture"] if url.endswith(":8080/v1/models") else []
        found = discover_local_backends(list_models=lookup)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0][1], "http://127.0.0.1:8080")
        self.assertEqual(len(queried), len(_DISCOVERY_ENDPOINTS))
        self.assertTrue(all(u.startswith("http://127.0.0.1:")
                            for u, _ in queried))
        self.assertTrue(all(t <= 2 for _, t in queried))

    def test_missing_or_protected_servers_remain_manual(self):
        lookup = Mock(side_effect=requests.HTTPError("401"))
        self.assertEqual(discover_local_backends(list_models=lookup), [])
        self.assertEqual(lookup.call_count, len(_DISCOVERY_ENDPOINTS))


if __name__ == "__main__":
    unittest.main()
