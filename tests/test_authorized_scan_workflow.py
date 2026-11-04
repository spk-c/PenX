"""PX-501 CI example is manual-only, explicit-consent and secret-safe.

These contract tests inspect the actual workflow file. They never activate
GitHub Actions, download a scanner or contact a target.
"""
from __future__ import annotations

from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "authorized-scan.yml"


class AuthorizedScanWorkflowContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.body = WORKFLOW.read_text(encoding="utf-8")

    def test_only_manual_dispatch_can_start_scan(self):
        self.assertIn("\non:\n  workflow_dispatch:\n", self.body)
        triggers = self.body.split("\non:\n", 1)[1].split("\npermissions:\n", 1)[0]
        for unsafe in ("pull_request:", "push:", "schedule:", "workflow_run:"):
            self.assertNotIn(unsafe, triggers)
        self.assertIn("if: inputs.authorized", self.body)
        self.assertIn("default: false", triggers)
        self.assertIn("SCAN_CONSENT: ${{ inputs.consent }}", self.body)

    def test_actions_are_commit_pinned_and_checkout_carries_no_token(self):
        self.assertRegex(self.body, r"uses: actions/checkout@[0-9a-f]{40}\b")
        self.assertRegex(self.body, r"uses: actions/setup-python@[0-9a-f]{40}\b")
        self.assertRegex(self.body, r"uses: github/codeql-action/upload-sarif@[0-9a-f]{40}\b")
        self.assertIn("persist-credentials: false", self.body)
        self.assertRegex(self.body, r"(?m)^permissions:\n  contents: read\n")
        self.assertIn("security-events: write", self.body)

    def test_bounded_hash_locked_scan_keeps_user_input_in_env(self):
        self.assertIn("--require-hashes -r requirements.lock.txt", self.body)
        self.assertIn("default: '4,5,d'", self.body)
        self.assertIn("SCAN_TARGET: ${{ inputs.target }}", self.body)
        self.assertIn("SCAN_KEYS: ${{ inputs.scanners }}", self.body)
        script = self.body.split("      - name: Collect authorized scanner observations", 1)[1]
        script = script.split("      - name: Upload SARIF", 1)[0]
        runnable = script.split("        run: |\n", 1)[1]
        self.assertNotIn("${{ inputs.", runnable)
        self.assertIn('--target "$SCAN_TARGET" --authorized', runnable)
        self.assertIn('--scanners "$SCAN_KEYS"', runnable)
        self.assertIn('--budget 600', runnable)
        self.assertIn('"\u0024{options[@]}"', runnable)
        self.assertIn("if [ \"$SCAN_CONSENT\" = true ]", runnable)

    def test_sarif_is_optional_and_exit_code_is_preserved(self):
        self.assertIn("hashFiles('scan-reports/*.sarif') != ''", self.body)
        self.assertIn("category: penx-authorized-scan", self.body)
        self.assertIn('echo "code=$code" >> "$GITHUB_OUTPUT"', self.body)
        self.assertIn('SCAN_EXIT: ${{ steps.scan.outputs.code }}', self.body)
        self.assertIn('exit "${SCAN_EXIT:-1}"', self.body)


if __name__ == "__main__":
    unittest.main()
