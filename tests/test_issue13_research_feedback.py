"""No-network contracts for the research-to-terminal feedback boundary."""
from __future__ import annotations

import unittest
from unittest.mock import Mock, patch
from penx_app.intelligence import search as research


class FakeDDGS:
    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def text(self, query, *, max_results):
        return [{"title": "Synthetic source",
                 "href": "https://example.invalid/advisory",
                 "body": "Offline fixture"}]


class ResearchFeedbackTests(unittest.TestCase):
    def test_search_progress_can_be_injected_without_print(self):
        seen = []
        with patch("builtins.print", side_effect=AssertionError("printed")):
            output = research.web_search(
                "fixture", ddgs_factory=FakeDDGS, emit=seen.append)
        self.assertIn("Synthetic source", output)
        self.assertEqual(seen, ["  [*] Searching: fixture"])

    def test_cve_search_has_scoped_progress_and_clients(self):
        seen = []
        search = Mock(return_value="Fixture search result")
        fetch = Mock(return_value="Fixture CVE page")
        with patch("builtins.print", side_effect=AssertionError("printed")):
            output = research.search_cve(
                "CVE-2024-9999", web_search_client=search,
                page_fetch_client=fetch, emit=seen.append)
        self.assertIn("Fixture search result", output)
        self.assertIn("Fixture CVE page", output)
        search.assert_called_once_with(
            "CVE-2024-9999 vulnerability exploit details", max_results=3)
        self.assertEqual(fetch.call_args.kwargs["max_chars"], 2000)
        self.assertEqual(seen, ["  [*] Looking up CVE-2024-9999..."])

    def test_dispatch_uses_injected_sources_without_network_or_console(self):
        seen = []
        search = Mock(return_value="Fixture result")
        fetch = Mock(return_value="Fixture details")
        with patch("builtins.print", side_effect=AssertionError("printed")), \
             patch.object(research.requests, "get",
                          side_effect=AssertionError("network call")):
            output = research.handle_search_dispatch(
                "CVE-2024-9999", general_search=search,
                page_fetch=fetch, emit=seen.append)
        self.assertIn("Fixture result", output)
        self.assertIn("Fixture details", output)
        self.assertEqual(seen, ["  [*] Looking up CVE-2024-9999..."])

    def test_default_terminal_message_remains_compatible(self):
        printed = []
        with patch("builtins.print", side_effect=printed.append):
            output = research.web_search("fixture", ddgs_factory=FakeDDGS)
        self.assertIn("Synthetic source", output)
        self.assertEqual(printed, ["  [*] Searching: fixture"])


if __name__ == "__main__":
    unittest.main()
