"""WordPress advisory API response lifetimes; all HTTP is mocked."""
from __future__ import annotations

import unittest
from unittest.mock import Mock

import requests

from penx_app.intelligence.wordpress_advisories import research_plugins


def _bound(response):
    """Build a transport that ignores all arguments and returns ``response``."""
    def _get(*_args, **_kwargs):
        return response
    return _get


FINGERPRINT = "MetaGenerator[Elementor 4.3.5]"


class WordpressAdvisoryResponseLifetimeTests(unittest.TestCase):
    def test_success_closes_connection(self):
        response = Mock()
        response.json.return_value = [{
            "cve_id": "CVE-2026-12345",
            "html_url": "https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
            "vulnerabilities": [],
        }]
        result = research_plugins(
            FINGERPRINT, http_get=lambda *args, **kwargs: response)
        self.assertEqual(result["checks"][0]["status"], "queried")
        self.assertEqual(len(result["candidates"]), 1)
        response.close.assert_called_once()

    def test_http_failure_still_closes_connection(self):
        response = Mock()
        response.raise_for_status.side_effect = requests.HTTPError("fixture 500")
        result = research_plugins(
            FINGERPRINT, http_get=lambda *args, **kwargs: response)
        self.assertEqual(result["checks"][0]["status"], "unavailable")
        response.close.assert_called_once()

    def test_bad_json_and_wrong_container_close_connection(self):
        for bad_json in (ValueError("invalid payload"), {"wrong": "shape"}):
            with self.subTest(response=str(bad_json)):
                response = Mock()
                if isinstance(bad_json, Exception):
                    response.json.side_effect = bad_json
                else:
                    response.json.return_value = bad_json
                result = research_plugins(
                    FINGERPRINT,
                    http_get=_bound(response))
                self.assertEqual(result["checks"][0]["status"], "unavailable")
                response.close.assert_called_once()

    def test_independent_responses_closed_for_multiple_supported_plugins(self):
        responses = [Mock(), Mock()]
        for response in responses:
            response.json.return_value = []
        get = Mock(side_effect=responses)
        result = research_plugins(
            FINGERPRINT + " PoweredBy[FlyingPress]", http_get=get)
        self.assertEqual([item["status"] for item in result["checks"]],
                         ["queried", "queried"])
        self.assertEqual(get.call_count, 2)
        for response in responses:
            response.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
