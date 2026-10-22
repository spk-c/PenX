"""Beginner guidance and consent flows with injected input and no live scans."""
import unittest
from unittest.mock import Mock, patch

from penx_app.application.scan_guidance import SCANNER_GUIDANCE, explain_profile, recommend_profile
from penx_app.cli.guided_scan import run_guided
from penx_app.scanners.registry import SCANNERS


class GuidedScanTests(unittest.TestCase):
    def guided(self, answers, *, available=True, target='example.test', code=0):
        output = []
        execute = Mock(return_value=code)
        with patch('penx_app.cli.guided_scan.build_preflight') as preflight, \
                patch('penx_app.cli.guided_scan.format_report', return_value='PREVIEW: no network used'):
            preflight.return_value.available = available
            result = run_guided(target=target, ask=Mock(side_effect=answers), emit=output.append, execute=execute)
        return result, output, execute, preflight

    def test_every_scanner_has_plain_language_guidance(self):
        self.assertEqual(set(SCANNER_GUIDANCE), set(SCANNERS))
        self.assertIn('Nmap', explain_profile(recommend_profile('1')))
        self.assertIn('third-party', explain_profile(recommend_profile('2')))
        self.assertEqual(recommend_profile('3').id, 'web_audit')
        self.assertEqual(recommend_profile('4').id, 'full_assessment')

    def test_first_inventory_requires_permission_preview_and_final_start(self):
        result, output, execute, preflight = self.guided(['', 'yes', 'yes'])
        self.assertEqual(result, 0)
        preflight.assert_called_once()
        execute.assert_called_once_with(['--target', 'example.test', '--authorized',
                                         '--profile', 'standard', '--output', './reports', '--format', 'both'])
        self.assertTrue(any('PREVIEW' in line for line in output))
        self.assertTrue(any('empty findings list does not mean secure' in line for line in output))

    def test_declined_permission_starts_neither_preflight_nor_scan(self):
        _, _, execute, preflight = self.guided(['1', 'no'])
        execute.assert_not_called()
        preflight.assert_not_called()

    def test_declined_active_consent_starts_nothing(self):
        _, _, execute, preflight = self.guided(['3', 'yes', 'no'])
        execute.assert_not_called()
        preflight.assert_not_called()

    def test_consented_web_audit_passes_explicit_consent(self):
        result, _, execute, preflight = self.guided(['3', 'yes', 'yes', 'yes'])
        self.assertEqual(result, 0)
        self.assertIn('--consent', execute.call_args.args[0])
        self.assertTrue(preflight.call_args.args[0].active_consent)

    def test_missing_scanners_need_explicit_partial_coverage_confirmation(self):
        _, _, execute, _ = self.guided(['1', 'yes', 'no'], available=False)
        execute.assert_not_called()
        result, _, execute, _ = self.guided(['1', 'yes', 'yes', 'yes'], available=False, code=4)
        self.assertEqual(result, 4)
        execute.assert_called_once()

    def test_final_start_defaults_to_no(self):
        _, _, execute, _ = self.guided(['1', 'yes', ''])
        execute.assert_not_called()

    def test_back_and_invalid_goal_never_execute(self):
        for goal in ('back', '\x1b', 'unknown'):
            _, _, execute, _ = self.guided([goal])
            execute.assert_not_called()

    def test_urls_subnets_ports_and_options_are_rejected(self):
        for target in ('https://example.test', '192.0.2.0/24', 'example.test:443', '-flags'):
            code, _, execute, preflight = self.guided([], target=target)
            self.assertEqual(code, 2)
            execute.assert_not_called()
            preflight.assert_not_called()

    def test_passive_profile_does_not_receive_active_consent(self):
        result, output, execute, _ = self.guided(['2', 'yes', 'yes'], code=5)
        self.assertEqual(result, 5)
        self.assertNotIn('--consent', execute.call_args.args[0])
        self.assertTrue(any('partial' in line for line in output))

    def test_input_interrupt_and_eof_never_execute(self):
        for error in (EOFError, KeyboardInterrupt):
            execute = Mock()
            self.assertEqual(run_guided(ask=Mock(side_effect=error), emit=lambda _: None, execute=execute), 5)
            execute.assert_not_called()

    def test_direct_guided_dispatch_bypasses_interactive_app_setup(self):
        from penx_app.bootstrap import main
        with patch('sys.argv', ['penx', 'guided', '--target', 'example.test']), \
                patch('penx_app.cli.guided_scan.main', return_value=0) as guided:
            self.assertEqual(main(), 0)
            guided.assert_called_once_with(['--target', 'example.test'])


if __name__ == '__main__':
    unittest.main()
