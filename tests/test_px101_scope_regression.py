"""PX-101 scope regression audit (C1): passive mode and redirect/discovery
authorization boundaries at the project-dispatch level.

These fixtures lock in the invariants the project policy must enforce even when
a plan is constructed by an external caller: a passive plan cannot schedule
active scanners or carry active consent, and a target that only appears as a
redirect or discovery is never authorized. All tests use disposable SQLite; no
network, subprocess, or real targets.
"""
from __future__ import annotations

from contextlib import closing
from dataclasses import replace
from pathlib import Path
import sqlite3
import tempfile
import unittest

from penx_app.application.project_dispatch import (
    ProjectDispatchPolicy,
    ProjectScopeDenied,
)
from penx_app.application.project_service import ProjectService
from penx_app.application.scan_profiles import (
    build_custom_plan,
    get_profile,
    profile_to_plan,
)
from penx_app.domain.project_scope import authorize, matching_approved_assets
from penx_app.storage.db_backend import SQLiteConnection
from penx_app.storage.project_repository import ProjectRepository
from penx_app.storage.schema_migrations import initialize_sqlite


class ProjectScopeRegressionTests(unittest.TestCase):
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

    def add(self, target="example.test", **kwargs):
        return self.service.add("audit", target, **kwargs)

    def policy(self):
        return ProjectDispatchPolicy("audit", self.service)

    def plan(self, target="example.test", keys=("4",), **kwargs):
        return build_custom_plan(target, keys, active_consent=False, **kwargs)

    def test_passive_project_plan_cannot_schedule_active_scanners(self):
        self.add()
        plan = profile_to_plan(get_profile("passive"), "example.test",
                               active_consent=False)
        # A passive plan must not carry active scanners; prepare() enforces R4.
        plan = replace(plan, scanner_keys=("4",))
        with self.assertRaisesRegex(
                ValueError, "passive-only plans cannot schedule active scanners"):
            self.policy().prepare(plan)

    def test_passive_project_plan_requires_no_active_consent(self):
        self.add()
        plan = profile_to_plan(get_profile("passive"), "example.test",
                               active_consent=False)
        plan = replace(plan, active_consent=True)
        with self.assertRaisesRegex(
                ValueError, "passive-only plans require active_consent to be False"):
            self.policy().prepare(plan)

    def test_redirect_target_never_authorized_by_project_scope(self):
        self.add("example.test")
        scope = self.service.scope("audit")
        # A target that only appears as a redirect Location (or discovery) is
        # not an approved asset, so it can never be dispatched for the project.
        self.assertFalse(authorize(scope, "foreign.invalid"))
        self.assertEqual(matching_approved_assets(scope, "foreign.invalid"), ())
        with self.assertRaises(ProjectScopeDenied):
            self.policy().prepare(self.plan(target="foreign.invalid"))


if __name__ == "__main__":
    unittest.main()
