"""Regression: project and backup commands must coexist after independent PRs merge."""
import sys
import unittest
from unittest.mock import patch

from penx_app.bootstrap import main


class BootstrapDispatchTests(unittest.TestCase):
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
