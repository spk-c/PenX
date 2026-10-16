"""No-network contracts for local LLM model discovery/provider boundaries."""
from __future__ import annotations

import unittest
from unittest.mock import Mock, patch

from penx_app.analysis.llm_client import (
    ModelConfigurationError, fetch_models, resolve_model_name,
)


def server_response(data):
    response = Mock()
    response.json.return_value = data
    return response


class ModelCataloguePortsTests(unittest.TestCase):
    def test_injected_http_get_preserves_auth_and_timeout(self):
        get = Mock(return_value=server_response({
            "data": [{"id": "qwen-local"}, {"id": ""}, {"id": 123}, "broken"]
        }))
        with patch("penx_app.analysis.llm_client.requests.get",
                   side_effect=AssertionError("live network attempted")):
            models = fetch_models(
                "http://127.0.0.1:8080/v1/models",
                api_key="secret-for-fixture", timeout=7, http_get=get)
        self.assertEqual(models, ["qwen-local"])
        self.assertEqual(get.call_args.args,
                         ("http://127.0.0.1:8080/v1/models",))
        self.assertEqual(get.call_args.kwargs["timeout"], 7)
        self.assertEqual(get.call_args.kwargs["headers"]["Authorization"],
                         "Bearer secret-for-fixture")

    def test_invalid_envelope_is_rejected_without_leaking_body(self):
        for response_data in ([], None, {"data": "bad"}, {"data": None}):
            with self.subTest(response_data=response_data):
                get = Mock(return_value=server_response(response_data))
                with self.assertRaisesRegex(ValueError, "valid 'data' list") as error:
                    fetch_models("http://127.0.0.1:8080/v1/models",
                                 http_get=get)
                self.assertNotIn("secret", str(error.exception).lower())

    def test_transport_error_is_not_retried_and_has_no_fallback_network(self):
        get = Mock(side_effect=TimeoutError("synthetic local outage"))
        with patch("penx_app.analysis.llm_client.requests.get",
                   side_effect=AssertionError("live network attempted")):
            with self.assertRaises(TimeoutError):
                fetch_models("http://127.0.0.1:8080/v1/models",
                             http_get=get)
        get.assert_called_once()

    def test_auto_lookup_is_per_call_and_explicit_id_is_offline(self):
        resolver = Mock(return_value=["single-model"])
        with patch("penx_app.analysis.llm_client.requests.get",
                   side_effect=AssertionError("live network attempted")):
            self.assertEqual(resolve_model_name(
                "auto", "http://127.0.0.1:8080/v1/models",
                model_list=resolver), "single-model")
            self.assertEqual(resolve_model_name(
                "named-model", "http://127.0.0.1:8080/v1/models",
                model_list=resolver), "named-model")
        resolver.assert_called_once_with(
            "http://127.0.0.1:8080/v1/models", api_key="")

    def test_ambiguous_models_are_not_automatically_selected(self):
        lookup = Mock(return_value=["first", "second"])
        with self.assertRaises(ModelConfigurationError):
            resolve_model_name("auto", "http://127.0.0.1:8080/v1/models",
                               model_list=lookup)
        lookup.assert_called_once()


if __name__ == "__main__":
    unittest.main()
