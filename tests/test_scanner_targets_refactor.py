"""Pure scanner normalization remains consistent with public tools API."""
import unittest
from unittest.mock import patch

from penx_app.scanners import scanner_targets
from penx_app.scanners import tools


class ScannerTargetModuleTests(unittest.TestCase):
    def test_cidr_scope_is_shared(self):
        self.assertEqual(scanner_targets.MAX_CIDR_ADDRESSES, tools.MAX_CIDR_ADDRESSES)
        for sample in ("example.test", "bücher.de", "192.0.2.1/24",
                       "2001:db8::1", "https://example.test/path"):
            with self.subTest(sample=sample):
                self.assertEqual(scanner_targets.normalize_host(sample), tools._host(sample))
        with self.assertRaisesRegex(ValueError, "CIDR target too large"):
            scanner_targets.normalize_host("0.0.0.0/0")

    def test_target_url_parsing_retains_explicit_endpoints(self):
        for sample in ("example.test:8443", "[2001:db8::1]:443",
                       "https://example.test/a?x=1"):
            with self.subTest(sample=sample):
                self.assertEqual(scanner_targets.normalize_web_target(sample), tools._web_target(sample))
                self.assertEqual(scanner_targets.target_urls(sample), tools._urls(sample))

    def test_wrappers_keep_patch_points_for_existing_scanner_tests(self):
        with patch("penx_app.scanners.tools._host", return_value="example.test") as host:
            self.assertEqual(tools._web_target("example.test:8443"), "example.test:8443")
            host.assert_called_once()
        with patch("penx_app.scanners.tools._web_target", return_value="example.test") as target:
            self.assertEqual(tools._urls("example.test"), [
                "https://example.test", "http://example.test"])
            target.assert_called_once_with("example.test")


if __name__ == "__main__":
    unittest.main(verbosity=2)
