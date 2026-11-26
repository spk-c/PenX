"""Regression: project and backup commands must coexist after independent PRs merge."""
import io
import sys
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from penx_app.bootstrap import main


class BootstrapDispatchTests(unittest.TestCase):
    def test_top_level_help_uses_platform_command_and_returns_success(self):
        for platform, executable in (("posix", "penx"), ("nt", "PenX.exe")):
            for flag in ("--help", "-h"):
                with self.subTest(platform=platform, flag=flag):
                    with (
                        patch("penx_app.bootstrap.os.name", platform),
                        patch.object(sys, "argv", [executable, flag]),
                        redirect_stdout(io.StringIO()) as output,
                    ):
                        self.assertEqual(main(), 0)
                    self.assertTrue(output.getvalue().startswith(f"Usage: {executable} "))

    def test_unknown_argument_still_returns_usage_error(self):
        with (
            patch.object(sys, "argv", ["penx", "--unknown-flag"]),
            redirect_stdout(io.StringIO()) as output,
        ):
            self.assertEqual(main(), 2)
        self.assertTrue(output.getvalue().startswith("Usage: "))

    def test_project_and_backup_dispatch_remain_available(self):
        choices = (
            ("project", "penx_app.application.project_service.main"),
            ("backup", "penx_app.application.backup_service.main"),
        )
        for command, target in choices:
            with self.subTest(command=command):
                with patch.object(sys, "argv", ["PenX.exe", command, "example"]):
                    with patch(target, return_value=17) as dispatched:
                        self.assertEqual(main(), 17)
                        dispatched.assert_called_once_with(["example"])


if __name__ == "__main__":
    unittest.main()
