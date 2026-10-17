"""Regression tests for cleanup of HTML research fetch connections."""
from __future__ import annotations

import unittest
from unittest.mock import Mock

import requests

from penx_app.intelligence.search import fetch_page


class ResearchPageConnectionContracts(unittest.TestCase):
    def test_success_closes_fetched_response(self):
        response = Mock()
        response.status_code = 200
        response.encoding = "utf-8"
        response.iter_content.side_effect = lambda **kw: iter([
            b"<html><script>ignore()</script><p>Useful evidence</p></html>",
        ])
        get = Mock(return_value=response)
        value = fetch_page("https://fixture.invalid/info", http_get=get)
        self.assertIn("Useful evidence", value)
        self.assertNotIn("ignore()", value)
        get.assert_called_once()
        response.close.assert_called_once()

    def test_http_failure_returns_warning_and_closes_response(self):
        response = Mock()
        response.status_code = 503
        response.raise_for_status.side_effect = requests.HTTPError("503 service unavailable")
        value = fetch_page("https://fixture.invalid/info",
                           http_get=lambda *args, **kwargs: response)
        self.assertIn("HTTP error", value)
        response.close.assert_called_once()

    def test_processing_error_still_closes_response(self):
        class BrokenResponse:
            def __init__(self):
                self.closed = False

            status_code = 200

            def raise_for_status(self):
                return None

            def iter_content(self, **_kwargs):
                raise ValueError("unusable encoding")

            def close(self):
                self.closed = True

        response = BrokenResponse()
        value = fetch_page("https://fixture.invalid/info",
                           http_get=lambda *args, **kwargs: response)
        self.assertIn("Fetch failed", value)
        self.assertTrue(response.closed)


if __name__ == "__main__":
    unittest.main()
