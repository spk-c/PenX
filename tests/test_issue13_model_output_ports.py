"""LLM CLI-output ports must be silent when the application injects emitters."""
from __future__ import annotations

import os
import unittest
from unittest.mock import Mock, patch

import requests
from penx_app.analysis import llm
from penx_app.analysis.llm_client import EmptyModelResponse


class ModelOutputPorts(unittest.TestCase):
    def test_live_text_and_progress_without_terminal_output(self):
        notifications = []
        chunks = []
        def transport(messages, **kwargs):
            self.assertTrue(callable(kwargs["stream_callback"]))
            kwargs["stream_callback"]("SUMMARY: safe")
            return "synthetic-model", "SUMMARY: safe"
        with patch.object(llm, "live_output", return_value=True), \
             patch("builtins.print", side_effect=AssertionError("terminal print")):
            result = llm.ask_llm(
                [{"role": "user", "content": "fixture"}],
                complete=transport, emit=notifications.append,
                stream_emit=chunks.append,
            )
        self.assertEqual(result, "SUMMARY: safe")
        self.assertEqual(chunks, ["SUMMARY: safe"])
        self.assertTrue(any("Response received" in x for x in notifications))

    def test_retry_port_preserves_messages_and_skips_second_sse_attempt(self):
        original = [{"role": "user", "content": "Synthetic authorized scan"}]
        snapshot = [dict(x) for x in original]
        transport = Mock(side_effect=[
            EmptyModelResponse(finish_reason="length", reasoning_seen=True),
            ("synthetic-model", "SUMMARY: stable"),
        ])
        notices = []
        with patch.dict(os.environ, {"PENX_LLM_RETRY_EMPTY": "on"}), \
             patch.object(llm, "live_output", return_value=False), \
             patch("builtins.print", side_effect=AssertionError("terminal print")):
            result = llm.ask_llm(original, complete=transport, emit=notices.append)
        self.assertEqual(result, "SUMMARY: stable")
        self.assertEqual(original, snapshot)
        self.assertEqual(transport.call_count, 2)
        self.assertNotIn("stream_callback", transport.call_args_list[-1].kwargs)
        self.assertIn("/no_think", transport.call_args_list[-1].args[0][-1]["content"])
        self.assertTrue(any("Retrying" in x for x in notices))

    def test_headless_timeout_returns_failure_without_stdout(self):
        transport = Mock(side_effect=requests.Timeout("offline timeout"))
        with patch.object(llm, "live_output", return_value=False), \
             patch("builtins.print", side_effect=AssertionError("terminal print")):
            result = llm.ask_llm(
                [{"role": "user", "content": "synthetic"}],
                complete=transport, emit=lambda value: None)
        self.assertTrue(result.startswith("[!]"))
        self.assertIn("timed out", result)
        transport.assert_called_once()


if __name__ == "__main__":
    unittest.main()
