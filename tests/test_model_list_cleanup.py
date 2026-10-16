"""Regression tests for HTTP response cleanup during model discovery."""
import unittest
from unittest.mock import Mock

import requests

from penx_app.analysis.llm_client import fetch_models


class ModelDiscoveryCleanupTests(unittest.TestCase):
    def test_success_releases_response(self):
        response = Mock()
        response.json.return_value = {"data": [{"id": "local-model"}]}
        self.assertEqual(fetch_models("http://127.0.0.1:8080/v1/models",
                                      http_get=lambda *a, **kw: response),
                         ["local-model"])
        response.close.assert_called_once()

    def test_invalid_json_releases_response(self):
        response = Mock()
        response.json.side_effect = ValueError("invalid JSON")
        with self.assertRaises(ValueError):
            fetch_models("http://127.0.0.1:8080/v1/models",
                         http_get=lambda *a, **kw: response)
        response.close.assert_called_once()

    def test_http_failure_releases_response(self):
        response = Mock()
        response.raise_for_status.side_effect = requests.HTTPError("403")
        with self.assertRaises(requests.HTTPError):
            fetch_models("http://127.0.0.1:8080/v1/models",
                         http_get=lambda *a, **kw: response)
        response.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
