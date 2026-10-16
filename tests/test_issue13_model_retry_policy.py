"""Offline contracts for the pure reasoning-only retry planner."""
import unittest
from penx_app.analysis.model_retry import prepare_empty_retry


class EmptyRetryTests(unittest.TestCase):
    def test_clones_user_message_and_preserves_scope(self):
        original = [{"role": "system", "content": "policy"},
                    {"role": "user", "content": "authorized fixture"}]
        before = [dict(x) for x in original]
        prepared, tokens = prepare_empty_retry(original, 8192, "16384")
        self.assertEqual(original, before)
        self.assertEqual(tokens, 16384)
        self.assertIn("/no_think", prepared[-1]["content"])
        self.assertIn("authorized target", prepared[-1]["content"])

    def test_retry_token_clamp_and_invalid_config(self):
        messages = [{"role": "user", "content": "fixture"}]
        self.assertEqual(prepare_empty_retry(messages, 2048, "-200")[1], 2048)
        self.assertEqual(prepare_empty_retry(messages, 2048, "bad")[1], 16384)
        self.assertEqual(prepare_empty_retry(messages, 2048, "999999")[1], 32768)

    def test_never_appends_to_nonuser_messages(self):
        original = [{"role": "system", "content": "policy"}]
        cloned, _ = prepare_empty_retry(original, 512, "1024")
        self.assertEqual(cloned, original)
        self.assertIsNot(cloned[0], original[0])


if __name__ == "__main__":
    unittest.main()
