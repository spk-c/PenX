"""Storage-owned connection lifecycle and optional correction feedback tests."""
import unittest
from unittest.mock import Mock

from penx_app.storage.correction_repository import load_correction_rules


class CorrectionConnectionTests(unittest.TestCase):
    def _run(self, first_rows, fallback_rows=(), error_at=None, engine="sqlite"):
        cursor = Mock()
        if error_at == "execute":
            cursor.execute.side_effect = RuntimeError("SQL failed")
        elif error_at == "fetch":
            cursor.fetchall.side_effect = RuntimeError("SQL fetch failed")
        else:
            cursor.fetchall.side_effect = [first_rows, fallback_rows]
        connection = Mock()
        connection.cursor.return_value = cursor
        factory = Mock(return_value=connection)
        try:
            result = load_correction_rules(connection_factory=factory, engine=engine)
        except RuntimeError:
            result = ""
            if error_at is None:
                raise
        factory.assert_called_once_with()
        connection.close.assert_called_once_with()
        return result, cursor

    def test_distilled_rules_close_connection(self):
        result, cursor = self._run([("Use evidence",)])
        self.assertIn("Use evidence", result)
        self.assertEqual(cursor.execute.call_count, 1)

    def test_fallback_rules_close_connection(self):
        result, cursor = self._run([], [("rejected", 2, "unsupported claim")])
        self.assertIn("unsupported claim", result)
        self.assertEqual(cursor.execute.call_count, 2)

    def test_empty_rules_close_connection(self):
        result, _ = self._run([], [])
        self.assertEqual(result, "")

    def test_execute_error_closes_connection(self):
        result, _ = self._run([], error_at="execute")
        self.assertEqual(result, "")

    def test_fetch_error_closes_connection(self):
        result, _ = self._run([], error_at="fetch")
        self.assertEqual(result, "")

    def test_mariadb_fallback_closes_connection(self):
        result, cursor = self._run([], [("rejected", 1, "reason")], engine="mariadb")
        self.assertIn("reason", result)
        self.assertIn("LEFT(c.reason, 80)", cursor.execute.call_args_list[1].args[0])


if __name__ == "__main__":
    unittest.main()
