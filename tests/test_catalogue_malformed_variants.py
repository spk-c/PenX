"""Malformed third-party catalogue payloads must be handled without crashes."""
import unittest
from unittest.mock import Mock

from penx_app.intelligence.cve_engine import osv_candidates, github_candidates
from penx_app.intelligence.cve_observations import parse_explicit_packages


class CatalogueParsingRegressions(unittest.TestCase):
    def setUp(self):
        self.package = parse_explicit_packages("pkg:pypi/requests@2.31.0")[0]

    def response(self, payload):
        result = Mock()
        result.json.return_value = payload
        return result

    def test_null_osv_page_token_ends_pagination(self):
        response = self.response({"vulns": [], "next_page_token": None})
        client = Mock(return_value=response)
        results, warning = osv_candidates(self.package, http_post=client)
        self.assertEqual((results, warning), ([], ""))
        client.assert_called_once()
        response.close.assert_called_once()

    def test_numeric_osv_page_token_is_invalid_not_a_query_parameter(self):
        response = self.response({"vulns": [], "next_page_token": 42})
        client = Mock(return_value=response)
        results, warning = osv_candidates(self.package, http_post=client)
        self.assertEqual(results, [])
        self.assertIn("malformed pagination token", warning)
        client.assert_called_once()
        response.close.assert_called_once()

    def test_nonstring_github_advisory_fields_fail_closed(self):
        for record in (
            {"cve_id": "CVE-2024-9999", "html_url": None},
            {"cve_id": 42,
             "html_url": "https://github.com/advisories/GHSA-abcd-efgh-ijkl"},
        ):
            with self.subTest(record=record):
                response = self.response([record])
                results, warning = github_candidates(
                    self.package, http_get=lambda *args, **kwargs: response)
                self.assertEqual(results, [])
                self.assertIn("malformed records", warning)
                response.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
