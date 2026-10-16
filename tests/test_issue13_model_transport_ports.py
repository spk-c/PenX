"""Issue #13: model transport ports, fail-closed errors and response lifetime.

All simulated local llama.cpp/Ollama/LM Studio responses are in-memory.
No network, scanner, external database, or real LLM is invoked.
"""
from __future__ import annotations

import json
import unittest
from unittest.mock import Mock, patch

import requests
from penx_app.analysis.llm_client import (
    EmptyModelResponse, IncompleteModelResponse, complete_chat,
)

CHAT = "http://127.0.0.1:8080/v1/chat/completions"
MODELS = "http://127.0.0.1:8080/v1/models"
MESSAGES = [{"role": "user", "content": "Synthetic passive review only"}]


def json_response(payload):
    response = Mock()
    response.json.return_value = payload
    response.raise_for_status.return_value = None
    return response


class StreamResponse:
    def __init__(self, lines, *, content_type="text/event-stream", json_payload=None):
        self.lines = list(lines)
        self.headers = {"content-type": content_type}
        self.payload = json_payload
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.closed = True
        return False

    def raise_for_status(self):
        return None

    def json(self):
        return self.payload

    def iter_lines(self, decode_unicode=False):
        assert decode_unicode is False
        yield from self.lines


def sse(events, done=True):
    rows = []
    for event in events:
        rows.extend([("data: " + json.dumps(event)).encode("utf-8"), b""])
    if done:
        rows.extend([b"data: [DONE]", b""])
    return StreamResponse(rows)


class ModelTransportPortContracts(unittest.TestCase):
    def invoke(self, *, post, model="synthetic-model", callback=None, lookup=None):
        with patch("penx_app.analysis.llm_client.requests.post",
                   side_effect=AssertionError("production HTTP POST used")), \
             patch("penx_app.analysis.llm_client.requests.get",
                   side_effect=AssertionError("production HTTP GET used")):
            return complete_chat(
                MESSAGES, url=CHAT, models_url=MODELS, model_name=model,
                api_key="fixture-private-key", timeout=43,
                max_tokens=2024, response_format={"type": "json_object"},
                http_post=post, model_list=lookup, stream_callback=callback)

    def test_nonstream_injected_client_and_model_lookup(self):
        response = json_response({"choices": [
            {"finish_reason": "stop", "message": {"content": "SUMMARY: offline"}}
        ]})
        post = Mock(return_value=response)
        lookup = Mock(return_value=["synthetic-model"])
        name, content = self.invoke(post=post, model="auto", lookup=lookup)
        self.assertEqual((name, content), ("synthetic-model", "SUMMARY: offline"))
        lookup.assert_called_once_with(MODELS, api_key="fixture-private-key")
        self.assertEqual(post.call_args.args, (CHAT,))
        kw = post.call_args.kwargs
        self.assertEqual(kw["timeout"], 43)
        self.assertEqual(kw["json"]["model"], "synthetic-model")
        self.assertEqual(kw["json"]["max_tokens"], 2024)
        self.assertEqual(kw["json"]["response_format"], {"type": "json_object"})
        self.assertFalse(kw["json"]["stream"])
        self.assertEqual(kw["headers"]["Authorization"], "Bearer fixture-private-key")
        response.close.assert_called_once()

    def test_explicit_model_never_uses_lookup(self):
        lookup = Mock(side_effect=AssertionError("explicit model should not list"))
        response = json_response({"choices": [
            {"message": {"content": "OK"}}
        ]})
        self.assertEqual(self.invoke(post=Mock(return_value=response),
                                     lookup=lookup), ("synthetic-model", "OK"))
        lookup.assert_not_called()

    def test_nonstream_invalid_envelopes_fail_closed_and_release_connection(self):
        for payload in (None, "SECRET raw body", [], {"choices": "SECRET"},
                        {"choices": None}):
            with self.subTest(payload=payload):
                response = json_response(payload)
                with self.assertRaisesRegex(ValueError, "malformed chat response") as err:
                    self.invoke(post=Mock(return_value=response))
                self.assertNotIn("SECRET", str(err.exception))
                response.close.assert_called_once()

    def test_nonstream_error_and_truncation_release_connection(self):
        response = json_response({"choices": [
            {"finish_reason": "content_filter", "message": {"content": "partial"}}
        ]})
        with self.assertRaises(IncompleteModelResponse):
            self.invoke(post=Mock(return_value=response))
        response.close.assert_called_once()

        response = json_response({"choices": [
            {"finish_reason": "length", "message": {"content": "partial"}}
        ]})
        with self.assertRaises(IncompleteModelResponse):
            self.invoke(post=Mock(return_value=response))
        response.close.assert_called_once()

    def test_nonstream_empty_answer_does_not_promote_reasoning(self):
        response = json_response({"choices": [
            {"finish_reason": "length",
             "message": {"content": None, "reasoning_content": "Private"}}
        ]})
        with self.assertRaises(EmptyModelResponse) as err:
            self.invoke(post=Mock(return_value=response))
        self.assertNotIn("Private", str(err.exception))
        response.close.assert_called_once()

    def test_timeout_propagates_with_no_hidden_retry(self):
        post = Mock(side_effect=requests.Timeout("synthetic timeout"))
        with self.assertRaises(requests.Timeout):
            self.invoke(post=post)
        post.assert_called_once()

    def test_sse_complete_stream_returns_text_and_closes(self):
        resp = sse([
            {"choices": [{"delta": {"reasoning_content": "hidden"}}]},
            {"choices": [{"delta": {"content": "SUMMARY: "}}]},
            {"choices": [{"delta": {"content": "clear"}}]},
            {"choices": [{"delta": {}, "finish_reason": "stop"}]},
        ])
        received = []
        result = self.invoke(post=Mock(return_value=resp), callback=received.append)
        self.assertEqual(result, ("synthetic-model", "SUMMARY: clear"))
        self.assertEqual(received, ["SUMMARY: ", "clear"])
        self.assertTrue(resp.closed)

    def test_sse_truncated_eof_does_not_return_partial_evidence(self):
        resp = sse([{"choices": [{"delta": {"content": "unverified partial"}}]}],
                   done=False)
        with self.assertRaises(IncompleteModelResponse):
            self.invoke(post=Mock(return_value=resp), callback=lambda value: None)
        self.assertTrue(resp.closed)

    def test_sse_malformed_frame_followed_by_done_is_not_success(self):
        resp = StreamResponse([
            b'data: {"choices": [{"delta": {"content": "part"}}]}', b"",
            b"data: NOT-JSON", b"", b"data: [DONE]", b"",
        ])
        with self.assertRaises(IncompleteModelResponse):
            self.invoke(post=Mock(return_value=resp), callback=lambda value: None)
        self.assertTrue(resp.closed)

    def test_sse_server_error_after_content_is_not_success(self):
        resp = StreamResponse([
            b'data: {"choices": [{"delta": {"content": "partial"}}]}', b"",
            b'event: error', b'data: {"error":"provider failed"}', b"",
            b"data: [DONE]", b"",
        ])
        with self.assertRaises(IncompleteModelResponse):
            self.invoke(post=Mock(return_value=resp), callback=lambda value: None)
        self.assertTrue(resp.closed)

    def test_sse_invalid_json_structures_never_complete_partial_text(self):
        invalid_frames = (
            None,
            ["invalid frame"],
            {"choices": "not-a-list"},
            {"choices": [42]},
            {"choices": [{"delta": ["not-an-object"]}]},
        )
        for frame in invalid_frames:
            with self.subTest(frame=frame):
                resp = sse([
                    {"choices": [{"delta": {"content": "unverified partial"}}]},
                    frame,
                ])
                with self.assertRaises(IncompleteModelResponse):
                    self.invoke(post=Mock(return_value=resp),
                                callback=lambda _delta: None)
                self.assertTrue(resp.closed)

    def test_sse_usage_only_frame_remains_supported(self):
        resp = sse([
            {"choices": [{"delta": {"content": "verified response"}}]},
            {"choices": [], "usage": {"completion_tokens": 2}},
            {"choices": [{"delta": {}, "finish_reason": "stop"}]},
        ])
        self.assertEqual(
            self.invoke(post=Mock(return_value=resp), callback=lambda _delta: None),
            ("synthetic-model", "verified response"),
        )
        self.assertTrue(resp.closed)

    def test_stream_non_sse_json_fallback_uses_injected_client(self):
        resp = StreamResponse(
            [], content_type="application/json",
            json_payload={"choices": [
                {"finish_reason": "stop", "message": {"content": "OK"}}
            ]})
        received = []
        self.assertEqual(self.invoke(post=Mock(return_value=resp),
                                     callback=received.append),
                         ("synthetic-model", "OK"))
        self.assertEqual(received, ["OK"])
        self.assertTrue(resp.closed)


if __name__ == "__main__":
    unittest.main()
