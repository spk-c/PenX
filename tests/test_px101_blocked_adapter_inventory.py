"""PX-101: project-mode adapter inventory and pre-I/O rejection (offline).

No network calls, external scanners or real targets. The frozen registry must
cover every tool-menu key when a new scanner is added.
"""
from __future__ import annotations

from unittest import TestCase, main
from unittest.mock import Mock, patch

from penx_app.application.project_dispatch import (
    PROJECT_REVIEW_REQUIRED_SCANNERS,
    PROJECT_SAFE_SCANNERS,
    ProjectDispatchPolicy,
)
from penx_app.application.scan_profiles import build_custom_plan
from penx_app.scanners.tools import TOOLS_MENU


class ProjectAdapterReviewGates(TestCase):
    def test_every_menu_scanner_has_an_explicit_project_review_disposition(self):
        self.assertFalse(PROJECT_SAFE_SCANNERS & PROJECT_REVIEW_REQUIRED_SCANNERS)
        self.assertEqual(
            set(TOOLS_MENU),
            PROJECT_SAFE_SCANNERS | PROJECT_REVIEW_REQUIRED_SCANNERS,
            "A new tool-menu key must receive a project-scope security review "
            "before being categorized for project use.",
        )
        self.assertEqual(
            PROJECT_SAFE_SCANNERS, frozenset({"4", "5", "8", "d"}))
        self.assertEqual(
            PROJECT_REVIEW_REQUIRED_SCANNERS,
            frozenset({"1", "2", "3", "6", "7", "9", "e", "s", "c"}),
        )

    def test_every_blocked_adapter_refused_before_scope_query_or_io(self):
        for key in sorted(PROJECT_REVIEW_REQUIRED_SCANNERS):
            with self.subTest(key=key):
                project = Mock()
                policy = ProjectDispatchPolicy("synthetic-project", project)
                plan = build_custom_plan(
                    "127.0.0.1", (key,), active_consent=True)
                with (
                    patch("subprocess.Popen") as process,
                    patch("requests.get") as get,
                    patch("requests.head") as head,
                    patch("socket.create_connection") as socket,
                ):
                    with self.assertRaisesRegex(
                        ValueError, "blocks scanners without verified scope"):
                        policy.prepare(plan)
                project.scope.assert_not_called()
                process.assert_not_called()
                get.assert_not_called()
                head.assert_not_called()
                socket.assert_not_called()

    def test_mixed_safe_and_blocked_plan_rejected_as_a_unit(self):
        project = Mock()
        plan = build_custom_plan(
            "127.0.0.1", ("4", "e"), active_consent=True)
        with patch("subprocess.Popen") as process:
            with self.assertRaisesRegex(ValueError, "blocks scanners"):
                ProjectDispatchPolicy("synthetic-project", project).prepare(plan)
        project.scope.assert_not_called()
        process.assert_not_called()


if __name__ == "__main__":
    main()
