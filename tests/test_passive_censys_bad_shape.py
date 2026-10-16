"""Malformed Censys metadata must not abort passive collection."""
from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from penx_app.scanners import passive_recon as passive


class PassiveCensysShapeTests(unittest.TestCase):
    def invoke(self, payload):
        def catalog(url, **_kwargs):
            if "search.censys.io" in url:
                return payload
            return {"name": "Synthetic RDAP fixture"}

        with patch.dict(os.environ, {
                "PENX_CENSYS_API_ID": "offline-id",
                "PENX_CENSYS_API_SECRET": "offline-secret",
            }), patch.object(passive, "_query_json", side_effect=catalog), \
             patch.object(passive, "enrich_target", return_value=[]):
            return passive.passive_recon("8.8.8.8", include_paid=True)

    def test_invalid_censys_services_does_not_abort_other_sources(self):
        for payload in (
            {"result": {"services": None}},
            {"result": {"services": "not-a-list"}},
            {"result": {"services": {}}},
            {"result": []},
            {"result": None},
        ):
            with self.subTest(payload=payload):
                result = self.invoke(payload)
                self.assertIn("[RDAP]", result)
                self.assertIn("[CENSYS] Unavailable: ValueError", result)
                self.assertNotIn("[CENSYS HISTORICAL INDEX]", result)

    def test_valid_service_list_is_preserved(self):
        result = self.invoke({
            "result": {"services": [{
                "port": 443, "service_name": "HTTPS",
                "transport_protocol": "TCP",
            }]}
        })
        self.assertIn("[CENSYS HISTORICAL INDEX]", result)
        self.assertIn("HTTPS", result)
        self.assertNotIn("[CENSYS] Unavailable", result)


if __name__ == "__main__":
    unittest.main()
