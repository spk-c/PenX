"""Repo housekeeping checks: one Windows build definition and clean artifacts."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import Mock, patch
import unittest

from scripts import build_windows


ROOT = Path(__file__).resolve().parents[1]


class RepositoryHygieneTests(unittest.TestCase):
    def test_single_builder_keeps_required_pyinstaller_options(self):
        args = build_windows.build_command()
        self.assertEqual(args[:3], [build_windows.sys.executable, "-m", "PyInstaller"])
        self.assertEqual(args[-1], "penx.py")
        self.assertIn("--onedir", args)
        self.assertIn("--paths", args)
        self.assertIn("src", args)
        self.assertEqual(args.count("--name"), 1)
        self.assertEqual(args[args.index("--name") + 1], "PenX")
        self.assertIn("--contents-directory", args)
        for flag in (
            "--hidden-import=penx_app.setup.first_run_setup",
            "--hidden-import=penx_app.setup.llm_setup",
            "--hidden-import=penx_app.setup.install_scanners_windows",
            "--hidden-import=whois",
            "--hidden-import=dns.resolver",
            "--hidden-import=debian.debian_support",
            "--hidden-import=rpm_vercmp",
        ):
            self.assertIn(flag, args)
        self.assertEqual([args[i + 1] for i, v in enumerate(args[:-1])
                          if v == "--collect-all"],
                         ["reportlab", "ddgs", "dns", "jsonschema", "defusedxml"])
        self.assertNotIn("--clean", args)

    def test_clean_flag_only_changes_local_build(self):
        ordinary = build_windows.build_command()
        clean = build_windows.build_command(clean=True)
        self.assertEqual(clean[:-2], ordinary[:-1])
        self.assertEqual(clean[-2:], ["--clean", "penx.py"])

    def test_builder_uses_argv_and_propagates_exit_status(self):
        with patch.object(build_windows.subprocess, "run",
                          return_value=Mock(returncode=7)) as runner:
            self.assertEqual(build_windows.main(["--clean"]), 7)
        args, kwargs = runner.call_args
        self.assertEqual(args[0], build_windows.build_command(clean=True))
        self.assertEqual(kwargs["cwd"], ROOT)
        self.assertFalse(kwargs["check"])
        self.assertNotIn("shell", kwargs)

    def test_shared_builder_used_by_all_entrypoints(self):
        for path, expected in (
            ("build-exe.bat", "scripts\\build_windows.py --clean"),
            (".github/workflows/ci.yml", "python scripts/build_windows.py"),
            (".github/workflows/release.yml", "python scripts/build_windows.py"),
        ):
            with self.subTest(path=path):
                content = (ROOT / path).read_text(encoding="utf-8")
                self.assertIn(expected, content)
                self.assertNotIn("-m PyInstaller", content)

    def test_manual_demo_is_opt_in_and_generates_only_ignored_files(self):
        workflow = (ROOT / ".github/workflows/record-localhost-demo.yml").read_text()
        self.assertIn("workflow_dispatch:", workflow)
        self.assertNotIn("feat/localhost-workflow-video-20261014", workflow)
        self.assertNotIn("  push:", workflow)
        ignored = (ROOT / ".gitignore").read_text()
        self.assertIn("/localhost_demo_video/", ignored)
        self.assertIn("/demo_output/", ignored)
        self.assertIn("/reports/", ignored)
        self.assertIn("/data/", ignored)
        self.assertIn(".env", ignored)

    def test_developer_guide_mentions_canonical_build_and_labels(self):
        guide = (ROOT / "docs/DEVELOPMENT.md").read_text(encoding="utf-8")
        self.assertIn("scripts/build_windows.py", guide)
        self.assertIn("triage:partially-supported", guide)
        self.assertIn("triage:audit", guide)
        self.assertIn("/penx-triage", guide)


if __name__ == "__main__":
    unittest.main(verbosity=2)
