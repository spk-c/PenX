"""Headless CI contracts with mock adapters, no network or real scanners."""
from contextlib import redirect_stdout
from io import StringIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from jsonschema import Draft202012Validator

from penx_app.application.headless_scan import main, policy_exit, scan_report
from penx_app.application.scan_profiles import build_custom_plan
from penx_app.domain.scan_models import ScanResult, ScannerResult
from penx_app.reporting.machine_reports import report_payload

ROOT = Path(__file__).resolve().parents[1]


def outcome(status='COMPLETE', text='TEMPLATE sample-id | high | Sample observation | https://example.test/path'):
    return ScanResult((ScannerResult('nuclei', text, status, status != 'FAILED', 'Nuclei'),))


class HeadlessScanTests(unittest.TestCase):
    def run_cli(self, arguments, result=None):
        with patch('penx_app.application.headless_scan.run_plan', return_value=result or outcome()) as runner, \
                redirect_stdout(StringIO()):
            code = main(arguments)
        return code, runner

    def test_authorization_and_consent_gate_before_adapters(self):
        for args in (['--target', 'example.test'],
                     ['--target', 'example.test', '--scanners', '7', '--authorized'],
                     ['--target', '-injected', '--authorized'],
                     ['--target', 'example.test', '--authorized', '--max-parallelism', '0'],
                     ['--target', 'example.test', '--authorized', '--profile', 'unknown'],
                     ['--target', 'example.test', '--authorized', '--profile', 'standard', '--scanners', '1']):
            with self.subTest(args=args):
                code, runner = self.run_cli(args)
                self.assertEqual(code, 2)
                runner.assert_not_called()

    def test_success_and_policy_reports_validate_and_never_overwrite(self):
        schema = json.loads((ROOT / 'docs/schemas/penx-scan-v1.schema.json').read_text())
        Draft202012Validator.check_schema(schema)
        with tempfile.TemporaryDirectory() as root:
            args = ['--target', 'example.test', '--authorized', '--consent', '--scanners', '7',
                    '--output', root, '--format', 'both', '--fail-on', 'high']
            for _ in range(2):
                code, runner = self.run_cli(args)
                self.assertEqual(code, 3)
                runner.assert_called_once()
            self.assertEqual(len(list(Path(root).iterdir())), 4)
            payload = json.loads((Path(root) / 'penx_scan.json').read_text())
            Draft202012Validator(schema).validate(payload)
            self.assertEqual(payload['profile']['profile_id'], 'custom')
            sarif = json.loads((Path(root) / 'penx_scan.sarif').read_text())
            finding = sarif['runs'][0]['results'][0]
            self.assertEqual(finding['level'], 'error')
            self.assertEqual(finding['partialFingerprints']['penxFinding/v1'], payload['findings'][0]['fingerprint'])

    def test_error_and_partial_coverage_take_priority_over_policy(self):
        for status, expected in (('FAILED', 4), ('PARTIAL', 5), ('COMPLETE', 3)):
            result = outcome(status)
            self.assertEqual(policy_exit(result, [{'severity': 'critical'}], 'high'), expected)
        self.assertEqual(policy_exit(outcome(), [{'severity': 'low'}], 'high'), 0)
        self.assertEqual(policy_exit(outcome(), [{'severity': 'high'}], None), 0)
        self.assertEqual(policy_exit(ScanResult(()), [], None), 5)

    def test_failed_adapter_prose_does_not_become_a_finding(self):
        plan = build_custom_plan('example.test', ('7',), active_consent=True)
        for result in (outcome('FAILED'), outcome(text='An error mentioned high severity'),
                       ScanResult((ScannerResult('nmap', outcome().results[0].text, 'COMPLETE', True),))):
            self.assertEqual(scan_report(plan, result)['findings'], [])

    def test_finding_limit_and_target_redaction(self):
        plan = build_custom_plan('example.test', ('7',), active_consent=True)
        text = '\n'.join(outcome().results[0].text.replace('sample-id', 'sample-' + str(i)) for i in range(1100))
        report = scan_report(plan, outcome(text=text), redact=True)
        self.assertEqual(len(report['findings']), 1000)
        self.assertNotIn('example.test', json.dumps(report))

    def test_dry_run_never_dispatches_or_requires_authorization(self):
        with patch('penx_app.application.headless_scan.build_preflight') as preflight, \
                patch('penx_app.application.headless_scan.format_report', return_value='dry run'):
            preflight.return_value.available = True
            code, runner = self.run_cli(['--target', 'example.test', '--dry-run'])
            self.assertEqual(code, 0)
            runner.assert_not_called()

    def test_passive_profile_uses_no_active_adapter_and_keeps_coverage_uncertain(self):
        with tempfile.TemporaryDirectory() as root, \
                patch('penx_app.application.passive_execution.run_passive_plan', return_value=outcome('PARTIAL')) as passive:
            code, runner = self.run_cli(['--target', 'example.test', '--authorized', '--profile', 'passive', '--output', root])
            self.assertEqual(code, 5)
            runner.assert_not_called()
            passive.assert_called_once()
            self.assertTrue(passive.call_args.args[0].passive_only)

    def test_report_failure_and_interrupt_have_documented_codes(self):
        with patch('penx_app.application.headless_scan.publish_unique', side_effect=OSError):
            code, _ = self.run_cli(['--target', 'example.test', '--authorized'])
            self.assertEqual(code, 1)
        with patch('penx_app.application.headless_scan.run_plan', side_effect=KeyboardInterrupt), redirect_stdout(StringIO()):
            self.assertEqual(main(['--target', 'example.test', '--authorized']), 5)

    def test_saved_assessment_standalone_schema_matches_real_export(self):
        data = {'history': (1, 'example.test', '2026-10-22', 'active'),
                'summary': (1, 1, '', '', 'LOW'), 'vulns': [
                    (1, 1, 'Example hypothesis', 'low', 'possible', '80', 'http', 'No evidence')],
                'fixes': [], 'corrections': []}
        schema = json.loads((ROOT / 'docs/schemas/penx-assessment-v1.schema.json').read_text())
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(report_payload(data))
        invalid = report_payload(data)
        invalid['session'] = None
        self.assertFalse(Draft202012Validator(schema).is_valid(invalid))

    def test_bootstrap_dispatch_does_not_enter_interactive_mode(self):
        from penx_app.bootstrap import main as bootstrap
        with patch('sys.argv', ['penx', 'scan', '--target', 'example.test']), \
                patch('penx_app.application.headless_scan.main', return_value=2) as command:
            self.assertEqual(bootstrap(), 2)
            command.assert_called_once_with(['--target', 'example.test'])

    def test_passive_parallelism_rejected_before_collection(self):
        with patch('penx_app.application.passive_execution.run_passive_plan') as passive:
            code, runner = self.run_cli(['--target', 'example.test', '--authorized',
                                         '--profile', 'passive', '--max-parallelism', '2'])
        self.assertEqual(code, 2)
        passive.assert_not_called()
        runner.assert_not_called()

    def test_optional_workflow_requires_manual_authorization_and_quotes_inputs(self):
        text = (ROOT / '.github/workflows/authorized-scan.yml').read_text()
        self.assertIn('  workflow_dispatch:', text)
        self.assertNotIn('  pull_request:', text)
        self.assertNotIn('  push:', text)
        self.assertIn('if: inputs.authorized', text)
        self.assertIn('--target "$SCAN_TARGET"', text)
        self.assertIn('--scanners "$SCAN_KEYS"', text)
        self.assertIn('github/codeql-action/upload-sarif@', text)


if __name__ == '__main__':
    unittest.main()
