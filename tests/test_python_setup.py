"""Offline tests of the Windows Python repair process. No installation occurs."""
import tempfile
import sys
import unittest
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

import windows_python_setup as setup


def cp(code=0, out=''):
    return CompletedProcess([], code, out, '')


class PythonSetupTests(unittest.TestCase):
    def test_support_matrix_explicitly_rejects_315(self):
        self.assertIn((3, 13), setup.SUPPORTED)
        self.assertNotIn((3, 15), setup.SUPPORTED)

    def test_detection_rejects_315_even_when_on_path(self):
        with patch.object(setup, 'interpreter_candidates',
                          return_value=[['python'], ['py', '-3.13']]), \
             patch.object(setup, 'python_version',
                          side_effect=[(3, 15), (3, 13)]):
            self.assertEqual(setup.find_supported_python(), ['py', '-3.13'])

    def test_version_detection_uses_execution_not_file_name(self):
        with patch.object(setup, 'run', return_value=cp(0, '3.15\n')):
            self.assertEqual(setup.python_version(['python313.exe']), (3, 15))

    def test_backup_preserves_sibling_user_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            venv = root / '.venv'
            (venv / 'Scripts').mkdir(parents=True)
            (venv / 'Scripts' / 'python.exe').write_text('unused')
            (root / '.env').write_text('SECRET=keep')
            (root / 'data').mkdir()
            (root / 'data' / 'penx.db').write_bytes(b'private database')
            with patch.object(setup, 'ROOT', root), patch.object(setup, 'VENV', venv), \
                 patch.object(setup, 'PYTHON_VENV', venv / 'Scripts' / 'python.exe'), \
                 patch.object(setup, 'python_version', return_value=(3, 15)):
                backup = setup.backup_old_venv()
            self.assertTrue((backup / 'Scripts' / 'python.exe').exists())
            self.assertFalse(venv.exists())
            self.assertEqual((root / '.env').read_text(), 'SECRET=keep')
            self.assertEqual((root / 'data' / 'penx.db').read_bytes(), b'private database')

    def test_backup_does_not_overwrite_existing_backup(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            venv = root / '.venv'
            venv.mkdir()
            (root / '.venv-python315-backup').mkdir()
            with patch.object(setup, 'ROOT', root), patch.object(setup, 'VENV', venv), \
                 patch.object(setup, 'python_version', return_value=(3, 15)):
                backup = setup.backup_old_venv()
            self.assertEqual(backup.name, '.venv-python315-backup-1')

    def test_package_failure_prevents_false_success(self):
        with patch.object(setup, 'run', return_value=cp(1)):
            self.assertFalse(setup.install_dependencies())

    def test_bootstrap_imports_src_modules_in_subprocess(self):
        # Reproduces the regression after moving tools.py under src/. Run with
        # the current CI interpreter; don't create a Windows-only .venv.
        with patch.object(setup, 'PYTHON_VENV', Path(sys.executable)):
            self.assertTrue(setup.ensure_imports())

    def test_http_failure_triggers_repair_and_recheck(self):
        # Two pip upgrades, one failing independent HTTP import check,
        # then a targeted reinstall (no unrelated modules touched).
        calls = [cp(0), cp(0), cp(1), cp(0)]
        with patch.object(setup, 'run', side_effect=calls) as mocked_run, \
             patch.object(setup, 'ensure_imports', side_effect=[False, True]) as imports:
            self.assertTrue(setup.install_dependencies())
            self.assertEqual(imports.call_count, 2)
            self.assertEqual(mocked_run.call_count, 4)
            self.assertIn('--force-reinstall', mocked_run.call_args.args[0])

    def test_local_module_import_failure_does_not_reinstall_http_packages(self):
        with patch.object(setup, 'run', side_effect=[cp(0), cp(0), cp(0)]) as mocked_run, \
             patch.object(setup, 'ensure_imports', return_value=False):
            self.assertFalse(setup.install_dependencies())
            self.assertEqual(mocked_run.call_count, 3)
            self.assertIn(setup.HTTP_IMPORT_TEST, mocked_run.call_args.args[0])
            self.assertFalse(any('--force-reinstall' in call.args[0]
                                 for call in mocked_run.call_args_list))

    def test_http_import_repair_failure_returns_error(self):
        with patch.object(setup, 'run', side_effect=[cp(0), cp(0), cp(1), cp(1)]) as mocked_run, \
             patch.object(setup, 'ensure_imports', return_value=False):
            self.assertFalse(setup.install_dependencies())
            self.assertEqual(mocked_run.call_count, 4)

    def test_dependency_install_prefers_hash_locked_lockfile(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'requirements.txt').write_text('requests>=2\n', encoding='utf-8')
            (root / 'requirements.lock.txt').write_text('requests==2.31.0\n', encoding='utf-8')
            with patch.object(setup, 'ROOT', root):
                args = setup.dependency_install_args()
            self.assertIn('--require-hashes', args)
            self.assertTrue(args[-1].endswith('requirements.lock.txt'))

    def test_dependency_install_falls_back_to_requirements_txt(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'requirements.txt').write_text('requests>=2\n', encoding='utf-8')
            with patch.object(setup, 'ROOT', root):
                args = setup.dependency_install_args()
            self.assertNotIn('--require-hashes', args)
            self.assertTrue(args[-1].endswith('requirements.txt'))

    def test_import_test_places_src_on_sys_path_before_local_imports(self):
        self.assertIn('sys.path.insert(0, str(Path.cwd() / "src"))', setup.IMPORT_TEST)
        self.assertLess(setup.IMPORT_TEST.index('sys.path.insert'),
                        setup.IMPORT_TEST.index('import requests'))

    def test_venv_reuse_skips_rebuilding(self):
        with tempfile.TemporaryDirectory() as tmp:
            venv = Path(tmp) / '.venv'
            (venv / 'Scripts').mkdir(parents=True)
            python = venv / 'Scripts' / 'python.exe'
            python.touch()
            with patch.object(setup, 'VENV', venv), \
                 patch.object(setup, 'PYTHON_VENV', python), \
                 patch.object(setup, 'python_version', return_value=(3, 13)), \
                 patch.object(setup, 'run') as invoke:
                self.assertTrue(setup.ensure_venv(['py', '-3.13']))
                invoke.assert_not_called()

    def test_installer_checks_failures(self):
        root = Path(__file__).resolve().parent.parent
        installer = (root / 'install-windows.bat').read_text()
        self.assertIn('windows_python_setup.py', installer)
        self.assertIn('if errorlevel 1 goto :fail', installer)
        self.assertIn('if errorlevel 1 (', installer)
        self.assertIn('exit /b 2', installer)
        repair = (root / 'repair-python.bat').read_text()
        self.assertIn('windows_python_setup.py', repair)
        self.assertNotIn('install_scanners_windows.py', repair)


if __name__ == '__main__':
    unittest.main()
