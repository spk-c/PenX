"""PX-308: offline OpenAPI maps are declarations, never observed or authorized URLs."""
from __future__ import annotations

from contextlib import redirect_stdout
from copy import deepcopy
from hashlib import sha256
from io import StringIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from penx_app.analysis.openapi_contract_map import (
    MAX_FILE_BYTES, build_contract_map, read_local_contract,
)
from penx_app.application.openapi_contract_cli import main


def spec() -> dict:
    return {
        "openapi": "3.1.0",
        "info": {"title": "Local synthetic fixture", "version": "1.0"},
        "servers": [{"url": "https://user:secret@outside.invalid/"
                    "?api_key=TOPSECRET"}],
        "security": [{"BearerAuth": []}],
        "components": {"securitySchemes": {
            "BearerAuth": {"type": "http", "scheme": "bearer",
                           "description": "API token=TOPSECRET"}}},
        "paths": {
            "/v1/users/{userId}": {
                "parameters": [{"name": "userId", "in": "path",
                                "required": True, "schema": {"type": "string"}}],
                "get": {
                    "responses": {"200": {"description": "OK",
                                          "content": {"application/json": {
                                              "example": {"password": "TOPSECRET"}}}}},
                    "parameters": [{"name": "expand", "in": "query"},
                                   {"name": "Authorization", "in": "header"}],
                },
                "patch": {
                    "deprecated": True, "requestBody": {"content": {
                        "application/json": {"example": {"token": "TOPSECRET"}}}},
                    "security": [],
                },
            },
            "/public": {"get": {"security": []}},
        },
    }


def mapped(value: dict | None = None) -> dict:
    return build_contract_map(spec() if value is None else value,
                              source_sha256="a" * 64)


class OpenApiOfflineMapTests(unittest.TestCase):
    def test_parse_minimal_declarations_without_any_token_data(self):
        result = mapped()
        self.assertEqual(result["schema"], "penx-openapi-contract-map-v1")
        self.assertEqual(result["coverage"], "COMPLETE")
        self.assertEqual(result["declared_operations"], 3)
        self.assertEqual(result["mapped_operations"], 3)
        self.assertEqual(result["server_entries_ignored"], 1)
        self.assertFalse(result["scan_authorized"])
        self.assertFalse(result["vulnerability_verified"])
        self.assertEqual(result["network_requests"], 0)
        by_key = {(row["path_template"], row["method"]): row
                  for row in result["endpoints"]}
        user = by_key[("/v1/users/{userId}", "GET")]
        self.assertEqual(user["auth"], "auth-declared")
        self.assertEqual(user["auth_types_declared"], ["http"])
        self.assertEqual(user["query_parameters"], ["expand"])
        self.assertEqual(user["path_parameters"], ["userId"])
        self.assertEqual(by_key[("/v1/users/{userId}", "PATCH")]["auth"],
                         "none-declared")
        self.assertTrue(by_key[("/v1/users/{userId}", "PATCH")]["deprecated"])
        payload = json.dumps(result)
        for banned in ("outside.invalid", "TOPSECRET", "Authorization",
                       "user:secret", "password", '"example":'):
            self.assertNotIn(banned, payload)
        self.assertTrue(all(not row["request_performed"] for row in result["endpoints"]))

    def test_unresolved_ref_makes_coverage_partial(self):
        fixture = spec()
        fixture["paths"]["/external"] = {"$ref": "https://outside.invalid/bad.yaml"}
        fixture["paths"]["/v1/users/{userId}"]["post"] = {
            "parameters": [{"$ref": "#/components/parameters/Secret"}],
            "security": [{"Unknown": ["read"]}],
        }
        report = mapped(fixture)
        self.assertEqual(report["coverage"], "PARTIAL")
        self.assertGreater(report["unresolved_reference_items"], 0)
        self.assertTrue(next(row for row in report["endpoints"]
                             if row["method"] == "POST")["referenced_metadata_incomplete"])
        self.assertNotIn("outside.invalid", json.dumps(report))

    def test_openapi_auth_security_alternatives(self):
        fixture = spec()
        fixture["paths"]["/public"]["get"]["security"] = [
            {"BearerAuth": []}, {}]
        report = mapped(fixture)
        value = next(row for row in report["endpoints"]
                     if row["path_template"] == "/public")
        self.assertEqual(value["auth"], "none-declared")

    def test_unsupported_versions_path_traversal_url_and_unsafe_templates_fail(self):
        paths = ("/../secrets", "/%2e%2e", "/api?api_key=1",
                 "/path//repeat", "/api#fragment", "/x\\y",
                 "https://outside.invalid/", "/{}", "/{1bad}",
                 "/token/secret=123")
        for path in paths:
            fixture = spec()
            fixture["paths"][path] = {"get": {}}
            with self.subTest(path=path), self.assertRaises(ValueError):
                mapped(fixture)
        for version in ("2.0", "4.0.0", "3.2.0", True, "3.0.0-rc"):
            fixture = spec()
            fixture["openapi"] = version
            with self.subTest(version=version), self.assertRaises(ValueError):
                mapped(fixture)

    def test_auth_malformed_parameters_and_method_payload_fail_closed(self):
        mutations = [
            lambda v: v["paths"]["/public"]["get"].update(security=[{"BearerAuth": "secret"}]),
            lambda v: v["paths"]["/public"]["get"].update(security=["BearerAuth"]),
            lambda v: v["paths"]["/public"]["get"].update(security=[{}, "not-object"]),
            lambda v: v["paths"]["/public"]["get"].update(parameters="bad"),
            lambda v: v["paths"]["/public"]["get"].update(deprecated="yes"),
            lambda v: v["paths"]["/public"].update(head=[]),
            lambda v: v.update(paths={str(i): {} for i in range(301)}),
            lambda v: v.update(components={"securitySchemes": []}),
            lambda v: v.update(servers="https://token:secret@example.test"),
        ]
        for mutate in mutations:
            value = spec()
            mutate(value)
            with self.subTest(mutate=str(mutate)), self.assertRaises(ValueError):
                mapped(value)

    def test_large_contract_never_silently_claims_full_map(self):
        fixture = spec()
        fixture["paths"] = {
            "/v1/resource%03d" % n: {"get": {}} for n in range(210)}
        report = mapped(fixture)
        self.assertEqual(report["coverage"], "PARTIAL")
        self.assertEqual(report["declared_paths"], 210)
        self.assertEqual(report["mapped_operations"], 150)
        self.assertGreater(report["truncated_paths"], 0)
        self.assertTrue(all(row["source"] == "openapi-declaration-not-observed"
                            for row in report["endpoints"]))

    def test_many_operations_still_mark_truncation(self):
        fixture = spec()
        fixture["paths"] = {
            "/v1/item%03d" % n: {method: {} for method in (
                "get", "head", "options", "post", "put", "patch", "delete", "trace")}
            for n in range(220)}
        report = mapped(fixture)
        self.assertEqual(report["declared_operations"], 1760)
        self.assertEqual(report["mapped_operations"], 150 * 8)
        self.assertEqual(report["truncated_paths"], 70)
        self.assertEqual(report["coverage"], "PARTIAL")

    def test_read_strict_json_limits_duplicates_nonfinite_and_link(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "contract.json"
            raw = json.dumps(spec(), sort_keys=True).encode()
            f.write_bytes(raw)
            doc, digest = read_local_contract(f)
            self.assertEqual(digest, sha256(raw).hexdigest())
            self.assertEqual(doc["openapi"], "3.1.0")
            # Windows PowerShell 5.1 writes UTF-8 JSON with a BOM by default.
            f.write_bytes(b"\xef\xbb\xbf" + raw)
            windows_doc, windows_hash = read_local_contract(f)
            self.assertEqual(windows_doc["openapi"], "3.1.0")
            self.assertEqual(windows_hash, sha256(b"\xef\xbb\xbf" + raw).hexdigest())
            for body in (b'{"openapi":"3.0.0","openapi":"3.1.0"}',
                         b'{"x":NaN}', b'\xff', b'[' * 1000,
                         b'X' * (MAX_FILE_BYTES + 1)):
                f.write_bytes(body)
                with self.subTest(body=body[:15]), self.assertRaises(ValueError):
                    read_local_contract(f)
            real = Path(tmp) / "real.json"
            real.write_text("{}", encoding="utf-8")
            f.unlink()
            try:
                f.symlink_to(real)
            except (OSError, NotImplementedError):
                return
            with self.assertRaises(ValueError):
                read_local_contract(f)

    def test_cli_writes_bounded_report_without_network_or_replacement(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / "synthetic.json"
            file.write_text(json.dumps(spec()), encoding="utf-8")
            output = Path(tmp) / "reports"
            with (patch("socket.create_connection",
                        side_effect=AssertionError("no external network")) as net,
                  patch("subprocess.run",
                        side_effect=AssertionError("no subprocess")) as proc,
                  redirect_stdout(StringIO()) as logs):
                argv = ["--file", str(file), "--output", str(output)]
                self.assertEqual(main(argv), 0)
                self.assertEqual(main(argv), 0)
            net.assert_not_called()
            proc.assert_not_called()
            report_file = output / "penx_openapi_contract.json"
            report = json.loads(report_file.read_text(encoding="utf-8"))
            self.assertEqual(report["coverage"], "COMPLETE")
            self.assertNotIn("TOPSECRET", report_file.read_text(encoding="utf-8"))
            self.assertTrue((output / "penx_openapi_contract_1.json").is_file())
            self.assertNotIn("TOPSECRET", logs.getvalue())
            self.assertEqual(json.loads(file.read_text())["openapi"], "3.1.0")

    def test_cli_failure_no_partial_output_leak(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / "bad.json"
            file.write_text('{"openapi":"3.0.0","paths":{"/a":{"get":{"security":"key=SECRET"}}}}')
            output = Path(tmp) / "results"
            with redirect_stdout(StringIO()) as logs:
                self.assertEqual(main(["--file", str(file), "--output", str(output)]), 2)
            self.assertFalse(output.exists())
            self.assertNotIn("SECRET", logs.getvalue())


if __name__ == "__main__":
    unittest.main()
