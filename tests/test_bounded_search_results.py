"""Offline regression coverage for malformed and unbounded external search results."""
from __future__ import annotations

import unittest
from unittest.mock import MagicMock, Mock

from penx_app.intelligence.search import (
    MAX_SEARCH_QUERY_CHARS, MAX_SEARCH_RESULTS, web_search,
)


class SearchResultBoundaryTests(unittest.TestCase):
    def factory(self, result):
        context = MagicMock()
        context.__enter__.return_value.text.return_value = result
        return Mock(return_value=context), context

    def test_one_malformed_hit_does_not_discard_other_valid_results(self):
        factory, context = self.factory(iter([
            {"title": "Valid first", "href": "https://example.org/1", "body": "First snippet"},
            {"title": "missing href", "body": "not a complete result"},
            None,
            ["unexpected sequence"],
            {"title": "Valid second", "href": "https://example.org/2"},
        ]))
        found = web_search("synthetic fixture", max_results=5, ddgs_factory=factory,
                           emit=lambda _: None)
        self.assertIn("Valid first", found)
        self.assertIn("Valid second", found)
        self.assertIn("First snippet", found)
        self.assertNotIn("missing href", found)
        self.assertEqual(found.count("    URL     : "), 2)
        context.__enter__.return_value.text.assert_called_once_with(
            "synthetic fixture", max_results=5)

    def test_overproducing_provider_iterator_is_bounded(self):
        visited = []

        def entries():
            for i in range(1000):
                visited.append(i)
                yield {"title": f"hit {i}", "href": f"https://example.org/{i}",
                       "body": "content"}
        factory, _ = self.factory(entries())
        found = web_search("bounded", max_results=3, ddgs_factory=factory,
                           emit=lambda _: None)
        self.assertEqual(visited, [0, 1, 2])
        self.assertEqual(found.count("    URL     : "), 3)
        self.assertNotIn("hit 3", found)

    def test_provider_text_is_single_line_and_size_bounded(self):
        factory, _ = self.factory([{
            "title": "Title\n" + "x" * 1000,
            "href": "https://example.org/\r" + "y" * 2000,
            "body": "snippet\n" + "z" * 100000,
        }])
        found = web_search("fixture", ddgs_factory=factory, emit=lambda _: None)
        self.assertLess(len(found), 2500)
        self.assertIn("Title x", found)
        self.assertIn("Snippet : snippet z", found)
        self.assertNotIn("\r", found)

    def test_invalid_limits_and_query_rejected_without_provider_calls(self):
        provider = Mock(side_effect=AssertionError("Provider must not be called"))
        for query, limit in (
            ("", 5), ("a" * (MAX_SEARCH_QUERY_CHARS + 1), 5),
            (None, 5), ("fixture", 0), ("fixture", MAX_SEARCH_RESULTS + 1),
            ("fixture", True), ("fixture", "5"),
        ):
            with self.subTest(query=str(query)[:20], limit=limit):
                self.assertTrue(
                    web_search(query, max_results=limit,
                               ddgs_factory=provider).startswith("[!]"))
        provider.assert_not_called()

    def test_provider_exception_never_appears_verbatim_in_model_result(self):
        provider = Mock(side_effect=RuntimeError("private-access-token-value"))
        found = web_search("fixture", ddgs_factory=provider, emit=lambda _: None)
        self.assertIn("Search failed", found)
        self.assertNotIn("private-access-token-value", found)

    def test_no_valid_hits_is_diagnostic_not_search_evidence(self):
        factory, _ = self.factory([{"title": "Incomplete"}, False])
        self.assertTrue(
            web_search("fixture", ddgs_factory=factory,
                       emit=lambda _: None).startswith("[!]"))


if __name__ == "__main__":
    unittest.main()
