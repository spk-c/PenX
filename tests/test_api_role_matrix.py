"""PX-309: no target scanning; every HTTP interaction is a fake client."""
from __future__ import annotations

from contextlib import redirect_stdout
from copy import deepcopy
from io import StringIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import requests

from penx_app.application.api_role_matrix import (
    REPORT_SCHEMA, compare_roles, load_plan, validate_plan,
)
from penx_app.application.api_role_matrix_cli import main


def plan() -> dict:
    return {
        "schema": "penx-api-role-plan-v1",
        "origin": "http://127.0.0.1:18123/",
        "cases": [
            {"path": "/api/me", "expect": {
                "guest": "deny", "user": "allow", "admin": "allow"}},
            {"path": "/api/admin", "expect": {
                "guest": "deny", "user": "deny", "admin": "allow"}},
        ],
    }


TOKENS = {"user": "synthetic-user-token", "admin": "synthetic-admin-token"}


class FakeResponse:
    def __init__(self, code):
        self.status_code = code
        self.closed = False

    def close(self):
        self.closed = True


class FakeSession:
    def __init__(self, log, status):
        self.log = log
        self.status = status
        self.headers = {"User-Agent": "unexpected-global-default"}
        self.trust_env = True
        self.closed = False

    def get(self, url, **kwargs):
        self.log.append((url, kwargs, self))
        if isinstance(self.status, Exception):
            raise self.status
        self.response = FakeResponse(self.status)
        return self.response

    def close(self):
        self.closed = True


def factory(statuses, log):
    items = iter(statuses)

    def create():
        return FakeSession(log, next(items))

    return create


class RoleMatrixTests(unittest.TestCase):
    def test_exact_scoped_get_and_no_cookie_header_response_capture(self):
        calls = []
        # /me 403 200 200; /admin 401 403 204.
        f = factory((403, 200, 200, 401, 403, 204), calls)
        original = plan()
        result = compare_roles(
            original, source_sha256="a" * 64, authorized=True, consent=True,
            role_tokens=TOKENS, session_factory=f, clock=lambda: 0)
        self.assertEqual(original, plan())
        self.assertEqual(result["schema"], REPORT_SCHEMA)
        self.assertEqual(result["coverage"], "COMPLETE")
        self.assertEqual(result["attempted_requests"], 6)
        self.assertEqual(result["status_responses"], 6)
        self.assertEqual(result["suspected_excess_access"], 0)
        self.assertEqual(result["unexpected_denials"], 0)
        self.assertFalse(result["vulnerability_verified"])
        self.assertFalse(result["bola_idor_verified"])
        self.assertFalse(result["response_bodies_collected"])
        self.assertFalse(result["scan_grant_transferable"])
        self.assertEqual(len(calls), 6)
        self.assertEqual([url for url, _, _ in calls],
                         ["http://127.0.0.1:18123/api/me"] * 3 +
                         ["http://127.0.0.1:18123/api/admin"] * 3)
        self.assertNotIn("Authorization", calls[0][1]["headers"])
        self.assertEqual(calls[1][1]["headers"]["Authorization"],
                         "Bearer synthetic-user-token")
        self.assertEqual(calls[2][1]["headers"]["Authorization"],
                         "Bearer synthetic-admin-token")
        for _, args, session in calls:
            self.assertFalse(session.trust_env)
            self.assertEqual(session.headers, {})
            self.assertTrue(session.closed)
            self.assertTrue(session.response.closed)
            self.assertEqual(args["allow_redirects"], False)
            self.assertTrue(args["verify"])
            self.assertTrue(args["stream"])
            self.assertEqual(args["timeout"], (2, 5))
        serialized = json.dumps(result)
        for secret in TOKENS.values():
            self.assertNotIn(secret, serialized)
        self.assertNotIn("http://127.0.0.1:18123", serialized)

    def test_denied_but_success_status_is_a_suspected_mismatch_not_proof(self):
        calls = []
        result = compare_roles(
            plan(), source_sha256="a" * 64, authorized=True, consent=True,
            role_tokens=TOKENS,
            session_factory=factory((200, 200, 200, 401, 200, 200), calls),
            clock=lambda: 0)
        self.assertEqual(result["suspected_excess_access"], 2)
        self.assertFalse(result["vulnerability_verified"])
        self.assertEqual(result["coverage"], "COMPLETE")
        self.assertEqual(result["cases"][0]["roles"][0]["comparison"],
                         "possible-excess-access")
        self.assertEqual(result["cases"][1]["roles"][1]["comparison"],
                         "possible-excess-access")

    def test_unexpected_denial_separate_from_possible_excess_access(self):
        result = compare_roles(
            plan(), source_sha256="a" * 64, authorized=True, consent=True,
            role_tokens=TOKENS,
            session_factory=factory((403, 403, 200, 401, 403, 204), []),
            clock=lambda: 0)
        self.assertEqual(result["unexpected_denials"], 1)
        self.assertEqual(result["suspected_excess_access"], 0)
        self.assertEqual(result["cases"][0]["roles"][1]["comparison"],
                         "unexpected-denial")

    def test_redirect_missing_and_server_error_are_inconclusive(self):
        result = compare_roles(
            plan(), source_sha256="a" * 64, authorized=True, consent=True,
            role_tokens=TOKENS,
            session_factory=factory((302, 404, 500, 401, 403, 200), []),
            clock=lambda: 0)
        self.assertEqual(result["coverage"], "PARTIAL")
        self.assertEqual(result["suspected_excess_access"], 0)
        self.assertEqual(result["cases"][0]["roles"][0]["comparison"],
                         "inconclusive")

    def test_transport_errors_do_not_become_negative_security_results(self):
        calls = []
        result = compare_roles(
            plan(), source_sha256="a" * 64, authorized=True, consent=True,
            role_tokens=TOKENS,
            session_factory=factory(
                (requests.ConnectionError("Bearer synthetic-user-token"),
                 200, 200, 401, 403, 200), calls),
            clock=lambda: 0)
        self.assertEqual(result["coverage"], "PARTIAL")
        self.assertEqual(result["status_responses"], 5)
        self.assertEqual(result["cases"][0]["roles"][0]["comparison"],
                         "transport-error")
        self.assertTrue(calls[0][2].closed)
        self.assertNotIn("synthetic-user-token", json.dumps(result))

    def test_origin_scope_refuses_remote_lan_dns_ports_and_url_credentials(self):
        for origin in (
            "http://example.test:8000", "http://10.0.0.5:8000",
            "http://192.168.1.10/", "http://localhost:18123/",
            "http://127.0.0.2:18123", "http://user:pass@127.0.0.1:18123/",
            "http://127.0.0.1:0", "http://127.0.0.1:99999",
            "https://outside.invalid", "file:///tmp/private",
            "http://127.0.0.1:18123/api",
            "http://127.0.0.1:18123/?secret=1",
            "http://127.0.0.1:18123/#fragment",
            "http://127.0.0.1:18123/%2e",
            r"http://127.0.0.1\outside.invalid/",
        ):
            input_plan = plan()
            input_plan["origin"] = origin
            with self.subTest(origin=origin), self.assertRaises(ValueError):
                validate_plan(input_plan)

    def test_untrusted_path_templates_query_and_state_change_are_rejected(self):
        cases = (
            "/api/../secret", "/api/%2fsecret", "/api//double",
            "/api/users/{userId}", "/api?admin=1", "/api#frag",
            "/api/logout", "/api/delete-user", "/api/payments/checkout",
            "https://outside.invalid/api", r"/api/\evil",
            "/api/items/" + "a" * 128, "/api/./child",
        )
        for path in cases:
            fixture = plan()
            fixture["cases"][0]["path"] = path
            with self.subTest(path=path), self.assertRaises(ValueError):
                validate_plan(fixture)

    def test_bad_plan_and_expansion_fail_before_session_factory(self):
        invalid = []
        for bad in ([], {}, None, "yes"):
            fixture = plan()
            fixture["cases"] = bad
            invalid.append(fixture)
        fixture = plan()
        fixture["cases"] *= 4
        invalid.append(fixture)
        fixture = plan()
        fixture["cases"][0]["expect"]["admin"] = True
        invalid.append(fixture)
        fixture = plan()
        fixture["cases"][0]["expect"]["extra"] = "allow"
        invalid.append(fixture)
        fixture = plan()
        fixture["cases"].append(deepcopy(fixture["cases"][0]))
        invalid.append(fixture)
        fixture = plan()
        fixture["target"] = "https://remote.test"
        invalid.append(fixture)
        for fixture in invalid:
            with self.subTest(fixture=str(fixture)[:80]), self.assertRaises(ValueError):
                validate_plan(fixture)

    def test_missing_consent_tokens_and_budget_validate_before_requests(self):
        from unittest.mock import Mock
        client = Mock()
        cases = (
            {"authorized": False, "consent": True, "role_tokens": TOKENS},
            {"authorized": True, "consent": False, "role_tokens": TOKENS},
            {"authorized": True, "consent": True, "role_tokens": {"user": "x"}},
            {"authorized": True, "consent": True, "role_tokens": {"user": "a", "admin": "a"}},
            {"authorized": True, "consent": True, "role_tokens": {"user": "bad\r\nHeader:1", "admin": "ok"}},
            {"authorized": True, "consent": True, "role_tokens": {"user": "ok", "admin": ""}},
            {"authorized": True, "consent": True, "role_tokens": TOKENS, "timeout": True},
            {"authorized": True, "consent": True, "role_tokens": TOKENS, "budget": 999},
        )
        for values in cases:
            with self.subTest(values=str(values)[:70]), self.assertRaises(ValueError):
                compare_roles(plan(), source_sha256="a" * 64,
                              session_factory=client, **values)
        client.assert_not_called()

    def test_cumulative_budget_prevents_unrequested_followup(self):
        calls = []
        # Clock: deadline init 0, guest 0, subsequent checks after >60.
        times = iter((0, 0, 61, 61, 61, 61, 61))
        result = compare_roles(
            plan(), source_sha256="a" * 64, authorized=True, consent=True,
            role_tokens=TOKENS,
            session_factory=factory((403,), calls), clock=lambda: next(times),
            budget=60)
        self.assertEqual(result["attempted_requests"], 1)
        self.assertEqual(result["status_responses"], 1)
        self.assertEqual(result["coverage"], "PARTIAL")
        self.assertEqual(result["cases"][0]["roles"][1]["comparison"],
                         "budget-exhausted")
        self.assertEqual(len(calls), 1)

    def test_strict_local_file_and_hash_for_refused_duplicate_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "plan.json"
            body = json.dumps(plan(), sort_keys=True)
            f.write_text(body, encoding="utf-8")
            got, fingerprint = load_plan(f)
            self.assertEqual(got, plan())
            self.assertEqual(len(fingerprint), 64)
            f.write_text('{"schema":"x","schema":"y"}', encoding="utf-8")
            with self.assertRaises(ValueError):
                load_plan(f)
            f.write_bytes(b"X" * 32769)
            with self.assertRaises(ValueError):
                load_plan(f)

    def test_cli_fail_closed_before_file_published(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "plan.json"
            f.write_text(json.dumps(plan()), encoding="utf-8")
            destination = Path(tmp) / "results"
            with redirect_stdout(StringIO()) as output:
                self.assertEqual(main(["--plan", str(f), "--authorized",
                                       "--output-dir", str(destination)]), 2)
            self.assertFalse(destination.exists())
            self.assertNotIn("synthetic-user-token", output.getvalue())

    def test_cli_records_only_status_and_never_overwrites(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "plan.json"
            source.write_text(json.dumps(plan()), encoding="utf-8")
            report = compare_roles(
                plan(), source_sha256="a" * 64, authorized=True, consent=True,
                role_tokens=TOKENS,
                session_factory=factory((403, 200, 200, 401, 403, 200), []),
                clock=lambda: 0)
            out = Path(tmp) / "reports"
            with patch("penx_app.application.api_role_matrix_cli.compare_roles",
                       return_value=report) as comparator:
                args = ["--plan", str(source), "--authorized", "--consent",
                        "--output-dir", str(out)]
                self.assertEqual(main(args), 0)
                self.assertEqual(main(args), 0)
                self.assertEqual(comparator.call_count, 2)
            self.assertTrue((out / "penx_api_role_comparison.json").exists())
            self.assertTrue((out / "penx_api_role_comparison_1.json").exists())
            self.assertNotIn("synthetic-user-token",
                             (out / "penx_api_role_comparison.json").read_text())


if __name__ == "__main__":
    unittest.main()
