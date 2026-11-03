"""PX-101 opt-in project dispatch gates; all tests use disposable SQLite only."""

from contextlib import closing, redirect_stdout
from datetime import datetime, timedelta, timezone
from io import StringIO
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import Mock, patch

from penx_app.application.headless_scan import main as scan_main
from penx_app.application.project_dispatch import ProjectDispatchPolicy, ProjectScopeDenied
from penx_app.application.project_service import ProjectService
from penx_app.application.scan_planner import run_plan
from penx_app.application.scan_profiles import build_custom_plan
from penx_app.domain.project_scope import matching_approved_assets
from penx_app.domain.scan_models import ScannerOutput
from penx_app.storage.db_backend import SQLiteConnection
from penx_app.storage.project_repository import ProjectRepository
from penx_app.storage.schema_migrations import initialize_sqlite


class ProjectDispatchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dbpath = Path(self.tmp.name) / "testing.sqlite"
        with closing(sqlite3.connect(self.dbpath)) as conn:
            initialize_sqlite(conn)
        self.factory = lambda: SQLiteConnection(sqlite3.connect(self.dbpath))
        self.repo = ProjectRepository(self.factory)
        self.service = ProjectService(self.repo)
        self.service.create("audit")
        self.output_dir = str(Path(self.tmp.name) / "reports")

    def add(self, target="example.test", **kwargs):
        return self.service.add("audit", target, **kwargs)

    def policy(self):
        return ProjectDispatchPolicy("audit", self.service)

    def plan(self, target="example.test", keys=("4",), **kwargs):
        return build_custom_plan(target, keys, active_consent=False, **kwargs)

    def cli(self, *values):
        arguments = ["--target", "example.test", "--authorized", "--project", "audit",
                     "--scanners", "4", "--output", self.output_dir, *values]
        with redirect_stdout(StringIO()) as buffer:
            result = scan_main(arguments, connection_factory=self.factory)
        return result, buffer.getvalue()

    def test_revoke_between_head_and_get_blocks_second_http_request(self):
        self.add()
        policy=self.policy()
        plan=policy.prepare(self.plan(target="https://example.test", keys=("4",)))
        from penx_app.scanners.tools import TOOLS_MENU
        def first_head(*args, **kwargs):
            self.repo.delete_asset(
                self.repo.get_project("audit").id, "example.test", "host")
            return Mock(status_code=405, url="https://example.test",
                        headers={"Location": "https://foreign.invalid/"})
        with patch("requests.head", side_effect=first_head) as head, \
                patch("requests.get") as get:
            result=run_plan(plan, menu=TOOLS_MENU, project_policy=policy)
        head.assert_called_once()
        get.assert_not_called()
        self.assertEqual(result.results[0].status, "PARTIAL")
        self.assertEqual(result.results[0].reason, "scope_denied")

    def test_revoke_while_rate_limiter_waits_blocks_initial_outbound_call(self):
        self.add(max_rate=2)
        policy=self.policy()
        plan=policy.prepare(self.plan(keys=("4",)))
        from penx_app.scanners.tools import TOOLS_MENU
        def revoke(*args, **kwargs):
            self.repo.delete_asset(
                self.repo.get_project("audit").id, "example.test", "host")
        with patch("penx_app.scanners.project_rate.ProjectRateLimiter.acquire",
                   side_effect=revoke) as limiter, \
                patch("requests.head") as head, patch("requests.get") as get:
            result=run_plan(plan, menu=TOOLS_MENU, project_policy=policy)
        limiter.assert_called_once()
        head.assert_not_called()
        get.assert_not_called()
        self.assertEqual(result.results[0].status, "PARTIAL")
        self.assertEqual(result.results[0].reason, "scope_denied")

    def test_direct_run_plan_cannot_bypass_approval_preparation(self):
        self.add()
        plan=self.plan()
        policy=self.policy()
        menu={"4": ("http", Mock(return_value=ScannerOutput(
            "value", status="COMPLETE", evidence=True)))}
        with self.assertRaises(ProjectScopeDenied):
            run_plan(plan, menu=menu, project_policy=policy)
        menu["4"][1].assert_not_called()
        prepared=policy.prepare(plan)
        with self.assertRaises(ProjectScopeDenied):
            run_plan(__import__("dataclasses").replace(
                prepared, target="other.test"), menu=menu, project_policy=policy)
        menu["4"][1].assert_not_called()

    def test_passive_ipv6_literal_accepted_but_host_port_rejected(self):
        self.add("2001:db8::1")
        from penx_app.application.scan_profiles import get_profile, profile_to_plan
        plan=profile_to_plan(get_profile("passive"), "2001:db8::1",
                             active_consent=False)
        self.assertTrue(self.policy().prepare(plan).passive_only)
        with self.assertRaises(ValueError):
            self.policy().prepare(profile_to_plan(
                get_profile("passive"), "[2001:db8::1]:443",
                active_consent=False))

    def test_default_budget_always_bounded_to_3600(self):
        self.add(max_budget=5000)
        policy=self.policy()
        plan=policy.prepare(self.plan())
        self.assertEqual(plan.global_budget_seconds, 3600)

    def test_future_dated_and_expired_approvals_cannot_run(self):
        clock = datetime.now(timezone.utc)
        self.add(expires_at=(clock + timedelta(hours=1)).isoformat())
        with patch("penx_app.domain.project_scope._utc_now",
                   return_value=clock + timedelta(hours=2)):
            with self.assertRaises(ProjectScopeDenied):
                self.policy().prepare(self.plan())
        self.repo.delete_asset(self.repo.get_project("audit").id, "example.test", "host")
        self.service.add("audit", "example.test", now=clock + timedelta(hours=1))
        with patch("penx_app.domain.project_scope._utc_now", return_value=clock):
            with self.assertRaises(ProjectScopeDenied):
                self.policy().prepare(self.plan())

    def test_redirect_response_not_followed_in_safe_header_adapter(self):
        from penx_app.scanners.tools import run_curl_headers
        response = Mock(status_code=302, url="https://example.test",
                        headers={"Location": "https://foreign.invalid/"})
        with patch("requests.head", return_value=response) as head, \
                patch("requests.get") as get, \
                patch("penx_app.scanners.tools.project_rate_before_io") as rate:
            result = run_curl_headers("https://example.test")
        self.assertEqual(result.status, "COMPLETE")
        self.assertIn("302", str(result))
        self.assertEqual(head.call_count, 1)
        self.assertEqual(head.call_args.kwargs["allow_redirects"], False)
        rate.assert_called_once()
        get.assert_not_called()

    def test_rate_limiter_sequences_logical_calls(self):
        from penx_app.scanners.project_rate import ProjectRateLimiter
        limiter=ProjectRateLimiter(2.0)
        with patch("penx_app.scanners.project_rate.time.monotonic", return_value=0.0), \
                patch("penx_app.scanners.project_rate.time.sleep") as sleep:
            limiter.acquire()
            limiter.acquire()
        sleep.assert_called_once_with(0.5)

    def test_exact_approved_target_dispatches_one_mock_adapter(self):
        self.add()
        calls = []
        fake = {"4": ("http headers", lambda target: calls.append(target) or
                      ScannerOutput("HEAD 200", status="COMPLETE", evidence=True))}
        with patch("penx_app.scanners.tools.TOOLS_MENU", fake):
            status, report = self.cli()
        self.assertEqual(status, 0, report)
        self.assertEqual(calls, ["example.test"])
        self.assertIn("Report: ", report)

    def test_missing_approval_does_not_start_any_adapters(self):
        with patch("penx_app.application.headless_scan.run_plan") as runner, \
                patch("subprocess.Popen") as popen, \
                patch("requests.head") as web:
            status, report = self.cli()
        self.assertEqual(status, 2, report)
        runner.assert_not_called()
        popen.assert_not_called()
        web.assert_not_called()

    def test_unknown_project_and_storage_failure_fail_closed(self):
        with patch("penx_app.application.headless_scan.run_plan") as runner:
            args = ["--target", "example.test", "--authorized", "--project", "unknown",
                    "--scanners", "4"]
            with redirect_stdout(StringIO()):
                self.assertEqual(scan_main(args, connection_factory=self.factory), 2)
            runner.assert_not_called()
            self.add()
            def db_failure():
                raise OSError("database unavailable")
            with redirect_stdout(StringIO()):
                self.assertEqual(scan_main(args[:-3] + ["audit", "--scanners", "4"],
                                           connection_factory=db_failure), 2)
            runner.assert_not_called()

    def test_candidate_and_expired_approval_fail_before_adapter(self):
        self.add(as_candidate=True)
        with patch("penx_app.application.headless_scan.run_plan") as runner:
            self.assertEqual(self.cli()[0], 2)
            runner.assert_not_called()
        self.repo.delete_asset(self.repo.get_project("audit").id, "example.test", "host")
        self.add(expires_at=(datetime.now(timezone.utc) + timedelta(seconds=1)).isoformat())
        with patch("penx_app.application.project_dispatch.matching_approved_assets",
                   return_value=()) as matcher, \
                patch("penx_app.application.headless_scan.run_plan") as runner:
            self.assertEqual(self.cli()[0], 2)
            self.assertTrue(matcher.called)
            runner.assert_not_called()

    def test_rejected_target_shapes_and_scanner_paths(self):
        self.add("example.test")
        for target in ("other.test", "example.test:99999",
                       "https://example.test/path", "*.example.test",
                       "192.168.1.0/30", "https://user@example.test"):
            with self.subTest(target=target):
                with redirect_stdout(StringIO()):
                    rc = scan_main(["--target", target, "--authorized", "--project", "audit",
                                    "--scanners", "4"], connection_factory=self.factory)
                self.assertEqual(rc, 2)
        for key in "123456789esc":
            if key in "45d":
                continue
            with self.subTest(key=key), \
                    patch("penx_app.application.headless_scan.run_plan") as runner:
                with redirect_stdout(StringIO()):
                    rc = scan_main(["--target", "example.test", "--authorized",
                                    "--project", "audit", "--scanners", key],
                                   connection_factory=self.factory)
                self.assertEqual(rc, 2)
                runner.assert_not_called()

    def test_explicit_port_is_not_silently_dropped(self):
        self.add("example.test:8443")
        policy=self.policy()
        self.assertEqual(policy.prepare(self.plan("example.test:8443")).target,
                         "example.test:8443")
        for target, keys in (("example.test:443", ("4",)),
                             ("example.test:8443", ("5",))):
            with self.subTest(target=target, keys=keys), self.assertRaises(ValueError):
                self.policy().prepare(self.plan(target, keys))
        self.assertFalse(matching_approved_assets(self.service.scope("audit"),
                                                  "example.test:443"))

    def test_cidr_wildcard_grants_only_allow_concrete_member_not_network(self):
        self.add("192.168.1.0/30")
        self.add("*.example.test")
        for accepted in ("192.168.1.2", "api.example.test"):
            self.assertEqual(self.policy().prepare(self.plan(accepted)).target, accepted)
        for denied in ("192.168.1.0/30", "*.example.test", "a.b.example.test"):
            with self.subTest(denied=denied), self.assertRaises(ValueError):
                self.policy().prepare(self.plan(denied))

    def test_ambiguous_overlap_denies_instead_of_choosing_laxest(self):
        self.add("api.example.test")
        self.add("*.example.test")
        with self.assertRaisesRegex(ProjectScopeDenied, "ambiguous"):
            self.policy().prepare(self.plan("api.example.test"))

    def test_limits_only_tighten_and_force_sequential_dispatch(self):
        self.add(max_rate=2.0, max_budget=90)
        policy=self.policy()
        configured=self.plan(max_parallelism=5, global_budget_seconds=200,
                             dispatch_interval_seconds=0.1)
        limited=policy.prepare(configured)
        self.assertEqual(limited.max_parallelism, 1)
        self.assertEqual(limited.global_budget_seconds, 90)
        self.assertEqual(limited.dispatch_interval_seconds, 0.5)
        self.assertIsNotNone(policy.rate_limiter)
        self.assertEqual(policy.rate_limiter.interval, 0.5)
        with self.assertRaises(ValueError):
            policy.prepare(configured)

    def test_low_budget_rejected_without_network_and_rate_ceiling_rejected(self):
        self.add(max_budget=10)
        with self.assertRaises(ValueError):
            self.policy().prepare(self.plan())
        self.repo.delete_asset(self.repo.get_project("audit").id, "example.test", "host")
        self.add(max_rate=120)
        with self.assertRaises(ValueError):
            self.policy().prepare(self.plan())

    def test_revalidate_revoked_between_adapters_stops_remaining_dispatch(self):
        self.add()
        policy=self.policy()
        plan=policy.prepare(self.plan(keys=("4", "5")))
        started=[]
        def first(target, **kwargs):
            started.append("4")
            self.repo.delete_asset(self.repo.get_project("audit").id, "example.test", "host")
            return ScannerOutput("200", status="COMPLETE", evidence=True)
        def second(target, **kwargs):
            started.append("5")
            return ScannerOutput("SHOULD NOT RUN", status="COMPLETE", evidence=True)
        menu={"4": ("http", first), "5": ("dns", second)}
        result = run_plan(plan, menu=menu, project_policy=policy)
        self.assertEqual(started, ["4"])
        self.assertEqual([row.status for row in result.results],
                         ["COMPLETE", "PARTIAL"])
        self.assertEqual(result.results[-1].reason, "scope_denied")

    def test_revalidate_expiry_approval_change_or_storage_failure(self):
        self.add()
        policy=self.policy()
        policy.prepare(self.plan())
        self.repo.delete_asset(self.repo.get_project("audit").id, "example.test", "host")
        with self.assertRaises(ProjectScopeDenied):
            policy.check("example.test")

    def test_cancellation_during_scoped_rate_wait_is_partial(self):
        from threading import Event
        from penx_app.application.scanner_execution import _run_adapter
        event=Event()
        event.set()
        def adapter(target, *, cancel_event=None):
            raise InterruptedError("cancelled while waiting for rate")
        result=_run_adapter("headers", adapter, "example.test",
                            lambda *_: None, event, "http_headers")
        self.assertEqual(result.status, "PARTIAL")
        self.assertEqual(result.reason, "cancelled")
        self.assertFalse(result.evidence)

    def test_passive_revocation_between_providers_preserves_earlier_coverage(self):
        from penx_app.application.passive_execution import run_passive_plan
        from penx_app.application.scan_profiles import profile_to_plan, get_profile
        self.add()
        policy=self.policy()
        plan=policy.prepare(profile_to_plan(
            get_profile("passive"), "example.test", active_consent=False))
        calls=[]
        def fake_query(url, **kwargs):
            calls.append(url)
            # The first provider is DNS, so stub DNS below to revoke after
            # a complete provider instead of contacting a public resolver.
            return {}
        fake_dns=Mock()
        fake_dns.resolve.return_value=[]
        def dns_resolve(*args, **kwargs):
            # Revoke during the last DNS call, triggering the next check.
            if args[1]=="TXT":
                self.repo.delete_asset(self.repo.get_project("audit").id,
                                       "example.test", "host")
            return []
        fake_dns.resolve.side_effect=dns_resolve
        with patch("dns.resolver.resolve", side_effect=dns_resolve), \
                patch("penx_app.scanners.passive_recon._query_json", side_effect=fake_query):
            result=run_passive_plan(plan, project_policy=policy)
        self.assertEqual(calls, [])
        self.assertTrue(result.results)
        self.assertTrue(all(row.status=="PARTIAL" for row in result.results))
        self.assertTrue(all(row.reason=="scope_denied" for row in result.results))

    def test_active_requires_explicit_user_authorized_flag(self):
        self.add()
        with patch("penx_app.application.headless_scan.run_plan") as runner, \
                redirect_stdout(StringIO()):
            rc = scan_main(["--target", "example.test", "--project", "audit",
                            "--scanners", "4"], connection_factory=self.factory)
        self.assertEqual(rc, 2)
        runner.assert_not_called()

    def test_port_specific_tls_and_ipv6_idn_are_canonicalized(self):
        self.add("[2001:db8::1]:8443")
        self.add("xn--bcher-kva.example")
        p=self.policy().prepare(self.plan("[2001:db8::1]:8443", keys=("d",)))
        self.assertEqual(p.target, "[2001:db8::1]:8443")
        self.assertEqual(self.policy().prepare(self.plan("bücher.example")).target,
                         "bücher.example")

    def test_passive_provider_rechecks_revoked_project_policy(self):
        self.add()
        policy=self.policy()
        plan=policy.prepare(
            __import__("penx_app.application.scan_profiles", fromlist=["get_profile",
                      "profile_to_plan"]).profile_to_plan(
                __import__("penx_app.application.scan_profiles", fromlist=["get_profile"]).get_profile("passive"),
                "example.test", active_consent=False))
        from penx_app.application.passive_execution import run_passive_plan
        self.repo.delete_asset(self.repo.get_project("audit").id, "example.test", "host")
        with patch("penx_app.scanners.passive_recon._query_json") as network:
            with self.assertRaises(ProjectScopeDenied):
                run_passive_plan(plan, project_policy=policy)
            network.assert_not_called()


if __name__ == "__main__":
    unittest.main()
