"""Regression tests: a local Qwen thinking-only response must not kill a scan silently."""
from __future__ import annotations

import json
import os
import unittest
from unittest.mock import Mock, MagicMock, patch

from penx_app.analysis.llm_client import EmptyModelResponse, complete_chat, extract_chat_text
from llm import ask_llm


class StreamResponse:
    def __init__(self, chunks, content_type="text/event-stream"):
        self.events = chunks
        self.headers = {"content-type": content_type}
        self.raise_for_status = Mock()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def iter_lines(self, decode_unicode=False):
        for data in self.events:
            yield "data: " + json.dumps(data)
            yield ""
        yield "data: [DONE]"
        yield ""


def call_with_stream(callback):
    return complete_chat(
        [{"role": "user", "content": "Assess authorized example.test"}],
        url="http://localhost:8080/v1/chat/completions",
        models_url="http://localhost:8080/v1/models",
        model_name="local-qwen", max_tokens=8192, stream_callback=callback,
    )


class LLMEmptyResponseTests(unittest.TestCase):
    def test_reasoning_only_nonstream_fails_with_reason(self):
        data = {"choices": [{"finish_reason": "length", "message": {
            "content": None, "reasoning_content": "Internal reasoning not for display",
        }}], "usage": {
            "completion_tokens": 8192,
            "completion_tokens_details": {"reasoning_tokens": 8192}
        }}
        self.assertEqual(extract_chat_text(data), "")
        response = Mock()
        response.json.return_value = data
        with patch("penx_app.analysis.llm_client.requests.post", return_value=response):
            with self.assertRaises(EmptyModelResponse) as ctx:
                complete_chat(
                    [{"role": "user", "content": "Hello"}],
                    url="http://localhost:8080/v1/chat/completions",
                    models_url="http://localhost:8080/v1/models",
                    model_name="local-qwen",
                )
        self.assertEqual(ctx.exception.finish_reason, "length")
        self.assertTrue(ctx.exception.reasoning_seen)
        self.assertIn("PENX_MAX_TOKENS", str(ctx.exception))
        self.assertNotIn("Internal reasoning", str(ctx.exception))

    def test_stream_reasoning_only_fails_without_leaking_it(self):
        events = [
            {"choices": [{"delta": {"reasoning_content": "Private thought"},
                           "finish_reason": None}]},
            {"choices": [{"delta": {}, "finish_reason": "length"}],
             "usage": {"completion_tokens": 8192}},
        ]
        callback = Mock()
        with patch("penx_app.analysis.llm_client.requests.post", return_value=StreamResponse(events)):
            with self.assertRaises(EmptyModelResponse) as ctx:
                call_with_stream(callback)
        callback.assert_not_called()
        self.assertTrue(ctx.exception.reasoning_seen)
        self.assertEqual(ctx.exception.completion_tokens, 8192)
        self.assertEqual(ctx.exception.finish_reason, "length")

    def test_stream_ignores_reasoning_and_emits_final_chunks(self):
        events = [
            {"choices": [{"delta": {"reasoning": "Private thought"}}]},
            {"choices": [{"delta": {"content": "RISK_LEVEL: "}}]},
            {"choices": [{"delta": {"content": "LOW"}}]},
            {"choices": [{"delta": {}, "finish_reason": "stop"}]},
        ]
        sent = []
        with patch("penx_app.analysis.llm_client.requests.post", return_value=StreamResponse(events)):
            _, text = call_with_stream(sent.append)
        self.assertEqual(text, "RISK_LEVEL: LOW")
        self.assertEqual(sent, ["RISK_LEVEL: ", "LOW"])

    def test_non_sse_response_with_stream_callback(self):
        res = MagicMock()
        res.__enter__.return_value = res
        res.headers = {"content-type": "application/json"}
        res.json.return_value = {"choices": [{"message": {"content": "SUMMARY: fine"}}]}
        output = []
        with patch("penx_app.analysis.llm_client.requests.post", return_value=res):
            _, answer = call_with_stream(output.append)
        self.assertEqual(answer, "SUMMARY: fine")
        self.assertEqual(output, ["SUMMARY: fine"])

    def test_retries_once_without_stream_and_preserves_caller_messages(self):
        msgs = [{"role": "system", "content": "Authorized assessment only."},
                {"role": "user", "content": "TARGET: example.test"}]
        before = [dict(x) for x in msgs]
        failed = EmptyModelResponse(finish_reason="length", reasoning_seen=True,
                                    completion_tokens=8192)
        with patch.dict(os.environ, {"PENX_LIVE_OUTPUT": "1",
                                     "PENX_LLM_RETRY_EMPTY": "on",
                                     "PENX_LLM_RETRY_TOKENS": "16384"}), \
             patch("llm.complete_chat", side_effect=[
                 failed, ("local-qwen", "RISK_LEVEL: LOW\nSUMMARY: No verified CVEs")
             ]) as complete:
            result = ask_llm(msgs)
        self.assertEqual(result.splitlines()[0], "RISK_LEVEL: LOW")
        self.assertEqual(msgs, before)
        self.assertEqual(complete.call_count, 2)
        first, retry = complete.call_args_list
        self.assertIn("stream_callback", first.kwargs)
        self.assertNotIn("stream_callback", retry.kwargs)
        self.assertGreaterEqual(retry.kwargs["max_tokens"], 16384)
        self.assertIn("/no_think", retry.args[0][-1]["content"])

    def test_retry_off_fails_with_explanation(self):
        error = EmptyModelResponse(finish_reason="length", reasoning_seen=True)
        with patch.dict(os.environ, {"PENX_LLM_RETRY_EMPTY": "off"}), \
             patch("llm.complete_chat", side_effect=error) as call:
            result = ask_llm([{"role": "user", "content": "x"}])
        self.assertTrue(result.startswith("[!]"))
        self.assertEqual(call.call_count, 1)
        self.assertIn("thinking", result.lower())

    def test_two_empty_answers_report_specific_failure(self):
        error = EmptyModelResponse(finish_reason="length", reasoning_seen=True)
        with patch.dict(os.environ, {"PENX_LLM_RETRY_EMPTY": "on"}), \
             patch("llm.complete_chat", side_effect=[error, error]) as call:
            result = ask_llm([{"role": "user", "content": "x"}])
        self.assertEqual(call.call_count, 2)
        self.assertIn("final answer after retry", result.lower())
        self.assertIn("PENX_MAX_TOKENS", result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
