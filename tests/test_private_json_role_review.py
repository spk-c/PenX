"""PX-310: privacy and evidence classification on synthetic role JSON only."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import requests

from penx_app.analysis.private_json_role_review import (
    MAX_JSON_BYTES, inspect_json_fields, validate_pointers,
)
from penx_app.application.api_role_matrix import compare_roles, validate_plan
from penx_app.application.api_role_matrix_cli import main
from tests.test_api_role_matrix import TOKENS, plan


def json_plan():
    doc = plan()
    for case in doc["cases"]:
        case["protected_json_pointers"] = ["/data/accountId", "/data/owner"]
    return doc


class Response:
    def __init__(self, status=200, *, data=b'{"data":{"accountId":"DUMMY"}}',
                 content_type="application/json", advertised=None,
                 fail_read=False):
        self.status_code = status
        self.headers = {"Content-Type": content_type}
        if advertised is not None:
            self.headers["Content-Length"] = advertised
        self.data = data
        self.fail_read = fail_read
        self.closed = False
        self.read_calls = 0

    def iter_content(self, *, chunk_size):
        self.read_calls += 1
        if self.fail_read:
            raise requests.exceptions.ConnectionError("synthetic sensitive body")
        for pos in range(0, len(self.data), chunk_size):
            yield self.data[pos:pos + chunk_size]

    def close(self):
        self.closed = True


class Session:
    def __init__(self, response, calls):
        self.response = response
        self.calls = calls
        self.headers = {"Cookie": "never-send"}
        self.trust_env = True
        self.closed = False

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs, self.response, self))
        return self.response

    def close(self):
        self.closed = True


def factory(responses, calls):
    iterator = iter(responses)
    return lambda: Session(next(iterator), calls)


class JsonRoleReviewTests(unittest.TestCase):
    def test_valid_pointer_schema_never_accepts_wildcards_indexes_or_secrets(self):
        self.assertEqual(validate_pointers(["/data/accountId"]), ("/data/accountId",))
        for candidate in ([], ["/data/accountId"] * 2, ["/" + "a" * 150],
                          ["/a"] * 4, ["/a/0"], ["/data/*"],
                          ["/data/~1"], ["/data/../password"],
                          ["/query?token=secret"], ["https://evil.invalid"],
                          ["/data/" + "x" * 50], ["password"], None, "/data/id"):
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                validate_pointers(candidate)

    def test_legacy_schema_and_behavior_unchanged_without_opt_in(self):
        from tests.test_api_role_matrix import factory as statuses
        result = compare_roles(
            plan(), source_sha256="a" * 64, authorized=True, consent=True,
            role_tokens=TOKENS,
            session_factory=statuses((403, 200, 200, 401, 403, 200), []),
            clock=lambda: 0)
        self.assertEqual(result["schema"], "penx-api-role-matrix-v1")
        self.assertNotIn("json_inspection_enabled", result)
        self.assertTrue(all("json_inspection" not in row
                            for case in result["cases"] for row in case["roles"]))

    def test_explicit_opt_in_must_match_every_case_before_network(self):
        client = Mock()
        for doc, enabled in ((json_plan(), False), (plan(), True)):
            with self.assertRaises(ValueError):
                compare_roles(doc, source_sha256="a" * 64, authorized=True,
                              consent=True, role_tokens=TOKENS,
                              inspect_json=enabled, session_factory=client)
        client.assert_not_called()
        doc = json_plan()
        doc["cases"][0]["protected_json_pointers"] = ["/data/*"]
        with self.assertRaises(ValueError):
            validate_plan(doc)
        client.assert_not_called()

    def test_synthetic_forbidden_role_with_actual_field_is_a_lead_not_proof(self):
        calls = []
        dummy = b'{"data":{"accountId":"SECRETDUMMY","owner":"admin"}}'
        body = Response(data=dummy)
        responses = [body, Response(data=dummy), Response(data=dummy),
                     Response(403), Response(403), Response(data=dummy)]
        report = compare_roles(
            json_plan(), source_sha256="a" * 64, authorized=True, consent=True,
            role_tokens=TOKENS, inspect_json=True,
            session_factory=factory(responses, calls), clock=lambda: 0)
        self.assertEqual(report["schema"], "penx-api-role-matrix-json-v1")
        self.assertEqual(report["protected_json_presence_leads"], 1)
        self.assertEqual(report["suspected_excess_access"], 1)
        self.assertEqual(report["coverage"], "COMPLETE")
        self.assertEqual(report["attempted_requests"], 6)
        self.assertFalse(report["vulnerability_verified"])
        self.assertFalse(report["bola_idor_verified"])
        self.assertFalse(report["response_bodies_collected"])
        self.assertTrue(report["response_bodies_inspected_transiently"])
        self.assertFalse(report["raw_json_values_persisted"])
        first = report["cases"][0]["roles"][0]
        self.assertEqual(first["comparison"], "possible-excess-access")
        self.assertEqual(first["json_inspection"]["state"], "parsed")
        self.assertEqual(first["json_inspection"]["protected_fields"], [
            {"pointer": "/data/accountId", "observation": "present"},
            {"pointer": "/data/owner", "observation": "present"}])
        result_json = json.dumps(report)
        for forbidden in ("SECRETDUMMY", "synthetic-admin-token", "synthetic-user-token"):
            self.assertNotIn(forbidden, result_json)
        self.assertEqual(responses[3].read_calls, 0)
        self.assertEqual(responses[4].read_calls, 0)
        self.assertTrue(all(response.closed for response in responses))
        self.assertTrue(all(session.closed for *_, session in calls))

    def test_html_login_returned_as_200_is_not_json_evidence(self):
        responses = [Response(data=b"<h1>login</h1>", content_type="text/html"),
                     Response(data=b'{"data":{"accountId":"own"}}'),
                     Response(data=b'{"data":{"accountId":"own"}}'),
                     Response(403), Response(403), Response(data=b'{"data":{"accountId":"root"}}')]
        result = compare_roles(
            json_plan(), source_sha256="a"*64, authorized=True, consent=True,
            role_tokens=TOKENS, inspect_json=True,
            session_factory=factory(responses, []), clock=lambda: 0)
        self.assertEqual(result["coverage"], "PARTIAL")
        self.assertEqual(result["protected_json_presence_leads"], 0)
        self.assertEqual(result["suspected_excess_access"], 1)
        self.assertEqual(result["cases"][0]["roles"][0]["json_inspection"]["state"], "not-json")
        self.assertEqual(responses[0].read_calls, 0)

    def test_missing_expected_field_not_silent_success(self):
        responses = [
            Response(403), Response(data=b'{"data":{"message":"missing"}}'),
            Response(data=b'{"data":{"accountId":"owner"}}'),
            Response(403), Response(403), Response(data=b'{"data":{"accountId":"admin"}}'),
        ]
        report = compare_roles(
            json_plan(), source_sha256="a"*64, authorized=True, consent=True,
            role_tokens=TOKENS, inspect_json=True,
            session_factory=factory(responses, []), clock=lambda: 0)
        self.assertEqual(report["allow_role_expected_fields_missing"], 1)
        self.assertEqual(report["coverage"], "COMPLETE")

    def test_fail_closed_json_duplicate_keys_oversize_deep_and_malformed(self):
        pointers = ("/data/accountId",)
        for body, expected in (
            (b'{"data":{"accountId":1,"accountId":2}}', "invalid-json"),
            (b'{"data":{"accountId":NaN}}', "invalid-json"),
            (b'\xff', "invalid-json"),
            (b'["not-an-object"]', "invalid-json"),
            (b'{"x":' + b'[' * 16 + b'0' + b']' * 16 + b'}', "invalid-json"),
            (b'{"data":{"accountId":"x"}}' + b" " * MAX_JSON_BYTES, "oversize-json"),
        ):
            with self.subTest(body=body[:30]):
                state, fields = inspect_json_fields(Response(data=body), pointers)
                self.assertEqual(state, expected)
                self.assertEqual(fields, [])
        state, fields = inspect_json_fields(
            Response(data=b'{"data":{"accountId":"canary"}}',
                     advertised=str(MAX_JSON_BYTES+1)), pointers)
        self.assertEqual(state, "oversize-json")
        self.assertEqual(fields, [])

    def test_nested_json_null_empty_and_valid_zero(self):
        state, fields = inspect_json_fields(
            Response(data=b'{"data":{"a":null,"b":"","c":0,"d":false}}'),
            ("/data/a", "/data/b", "/data/c"))
        self.assertEqual(state, "parsed")
        self.assertEqual([x["observation"] for x in fields], ["null", "empty", "present"])

    def test_failed_json_read_marks_partial_without_publishing_errors(self):
        responses = [
            Response(403),
            Response(fail_read=True),
            Response(data=b'{"data":{"accountId":"ok"}}'),
            Response(403), Response(403), Response(data=b'{"data":{"accountId":"ok"}}'),
        ]
        report = compare_roles(
            json_plan(), source_sha256="a"*64, authorized=True, consent=True,
            role_tokens=TOKENS, inspect_json=True,
            session_factory=factory(responses, []), clock=lambda: 0)
        self.assertEqual(report["coverage"], "PARTIAL")
        self.assertEqual(report["cases"][0]["roles"][1]["json_inspection"]["state"], "body-read-error")
        self.assertNotIn("synthetic sensitive body", json.dumps(report))

    def test_cli_writes_new_report_with_opt_in_and_no_values(self):
        doc = json_plan()
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "plan.json"
            source.write_text(json.dumps(doc), encoding="utf-8")
            out = Path(tmp) / "out"
            expected = {
                "schema": "penx-api-role-matrix-json-v1", "coverage": "COMPLETE",
                "status_responses": 3, "suspected_excess_access": 0,
                "unexpected_denials": 0, "protected_json_presence_leads": 0,
                "allow_role_expected_fields_missing": 0,
                "vulnerability_verified": False,
            }
            with patch("penx_app.application.api_role_matrix_cli.compare_roles",
                       return_value=deepcopy(expected)) as tool:
                args = ["--plan", str(source), "--authorized", "--consent",
                        "--inspect-json", "--output-dir", str(out)]
                self.assertEqual(main(args), 0)
                self.assertEqual(main(args), 0)
                self.assertTrue(tool.call_args.kwargs["inspect_json"])
                self.assertEqual(len(list(out.glob("penx_api_role_comparison*.json"))), 2)


if __name__ == "__main__":
    unittest.main()
