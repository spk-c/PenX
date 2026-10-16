"""Bootstrap a supported, working Python environment on Windows for PenX.

Only standard-library imports: this script intentionally runs even if the currently
selected Python is 3.15 and its third-party packages are broken.

The installer prefers CPython 3.13, accepts 3.10-3.13, and does not alter the
system default Python or delete an incompatible virtual environment.
"""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys

from penx_app.app_paths import APP_ROOT
ROOT = APP_ROOT
VENV = ROOT / '.venv'
PYTHON_VENV = VENV / 'Scripts' / 'python.exe'
SUPPORTED = ((3, 13), (3, 12), (3, 11), (3, 10))
WINGET_PACKAGE = 'Python.Python.3.13'
# The repository keeps internal application modules under src/. Bootstrap
# subprocesses run with cwd=ROOT, so explicitly expose that source directory
# without modifying the user's global PYTHONPATH or installed packages.
IMPORT_TEST = ('import sys; from pathlib import Path; '
               'sys.path.insert(0, str(Path.cwd() / "src")); '
               'import requests, charset_normalizer, bs4, dotenv, dns, whois, '
               'ddgs, reportlab; '
               'import penx_app.scanners.tools; '
               'import penx_app.setup.windows_check; '
               'print("[OK] PenX Python imports verified")')
HTTP_IMPORT_TEST = ('import requests, charset_normalizer; '
                    'print("[OK] HTTP packages import successfully")')


def say(message: str) -> None:
    print(message, flush=True)


def run(args: list[str], *, timeout: int = 120, capture: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(args, cwd=str(ROOT), text=True,
                          stdout=subprocess.PIPE if capture else None,
                          stderr=subprocess.PIPE if capture else None,
                          errors='replace', timeout=timeout, check=False)


def python_version(command: list[str]) -> tuple[int, int] | None:
    """Ask a candidate executable what it really is; don't trust its filename."""
    try:
        result = run(command + ['-c', 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")'],
                     timeout=20, capture=True)
        if result.returncode == 0:
            major, minor = result.stdout.strip().split('.')
            return int(major), int(minor)
    except (OSError, subprocess.TimeoutExpired, ValueError, AttributeError):
        pass
    return None


def known_python_paths() -> list[str]:
    paths: list[str] = []
    for ver in SUPPORTED:
        suffix = f'{ver[0]}{ver[1]}'
        for base in (os.environ.get('LOCALAPPDATA'), os.environ.get('ProgramFiles'),
                     os.environ.get('ProgramW6432')):
            if base:
                paths.append(str(Path(base) / 'Programs' / 'Python' / f'Python{suffix}' / 'python.exe'))
                paths.append(str(Path(base) / f'Python{suffix}' / 'python.exe'))
    if os.name == 'nt':
        try:
            from importlib import import_module
            winreg = import_module("winreg")
            for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
                for ver in SUPPORTED:
                    keyname = f'Software\\Python\\PythonCore\\{ver[0]}.{ver[1]}\\InstallPath'
                    for access in (winreg.KEY_READ, winreg.KEY_READ | winreg.KEY_WOW64_64KEY):
                        try:
                            with winreg.OpenKey(hive, keyname, 0, access) as key:
                                try:
                                    executable, _ = winreg.QueryValueEx(key, 'ExecutablePath')
                                except OSError:
                                    installed_dir, _ = winreg.QueryValueEx(key, '')
                                    executable = str(Path(installed_dir) / 'python.exe')
                                paths.append(executable)
                        except OSError:
                            continue
        except ImportError:
            pass
    return paths


def interpreter_candidates() -> list[list[str]]:
    candidates: list[list[str]] = []
    if shutil.which('py'):
        candidates += [['py', f'-{major}.{minor}'] for major, minor in SUPPORTED]
    candidates += [[p] for p in known_python_paths() if Path(p).is_file()]
    # sys.executable is merely a fallback; may be a broken Python 3.15.
    candidates.append([sys.executable])
    for exe in ('python3.13', 'python3.12', 'python3.11', 'python3.10', 'python'):
        if shutil.which(exe):
            candidates.append([exe])
    return candidates


def find_supported_python() -> list[str] | None:
    # Prefer the most recent supported minor, irrespective of PATH ordering.
    found: dict[tuple[int, int], list[str]] = {}
    for command in interpreter_candidates():
        version = python_version(command)
        if version in SUPPORTED and version not in found:
            found[version] = command
    for version in SUPPORTED:
        if version in found:
            return found[version]
    return None


def install_python_with_winget() -> bool:
    winget = shutil.which('winget')
    if not winget or os.name != 'nt':
        say('[ERROR] Compatible Python 3.10-3.13 not found and winget is unavailable.')
        say('        Install Python 3.13 from https://www.python.org/downloads/windows/')
        return False
    say('[*] Installing Python 3.13 via the official winget package...')
    try:
        result = run([winget, 'install', '--id', WINGET_PACKAGE, '--exact',
                      '--accept-package-agreements', '--accept-source-agreements'],
                     timeout=1800)
    except (OSError, subprocess.TimeoutExpired) as exc:
        say(f'[ERROR] Python installation could not complete: {exc}')
        return False
    if result.returncode:
        say(f'[WARN] winget returned exit code {result.returncode}. Checking for Python 3.13 anyway...')
    return True


def backup_old_venv() -> Path:
    """Move the incompatible environment aside, never touching .env or data/."""
    existing = python_version([str(PYTHON_VENV)])
    suffix = f'{existing[0]}{existing[1]}' if existing else 'unknown'
    destination = ROOT / f'.venv-python{suffix}-backup'
    count = 1
    while destination.exists():
        destination = ROOT / f'.venv-python{suffix}-backup-{count}'
        count += 1
    VENV.rename(destination)
    say(f'[INFO] Existing incompatible environment backed up to: {destination.name}')
    return destination


def restore_venv_backup(backup: Path | None) -> bool:
    """Restore an old virtual environment if new creation/dependency setup fails.

    Preserve the incomplete replacement under a uniquely named quarantine
    directory for troubleshooting rather than overwriting any user data.
    """
    if backup is None:
        return False
    try:
        if VENV.exists() or VENV.is_symlink():
            if VENV.is_symlink():
                raise OSError("Refusing to move a symlink at the .venv destination")
            destination = ROOT / ".venv-install-failed"
            i = 1
            while destination.exists():
                destination = ROOT / f".venv-install-failed-{i}"
                i += 1
            VENV.rename(destination)
            say(f"[INFO] Incomplete environment preserved as {destination.name}")
        backup.rename(VENV)
        say("[INFO] Previous environment restored after setup failure.")
        return True
    except OSError as exc:
        say(f"[ERROR] Could not restore prior .venv: {exc}; backup is at {backup}")
        return False


def ensure_venv(python: list[str], *, backups: list[Path] | None = None) -> bool:
    backup = None
    if PYTHON_VENV.is_file():
        existing = python_version([str(PYTHON_VENV)])
        if existing in SUPPORTED:
            say(f'[OK] Reusing Python {existing[0]}.{existing[1]} environment in .venv')
            return True
        backup = backup_old_venv()
    elif VENV.exists():
        backup = backup_old_venv()
    if backup is not None and backups is not None:
        backups.append(backup)
    say(f'[*] Creating .venv using {" ".join(python)}')
    try:
        created = run([*python, '-m', 'venv', str(VENV)], timeout=300)
    except (OSError, subprocess.TimeoutExpired) as exc:
        say(f'[ERROR] Could not create virtual environment: {exc}')
        restore_venv_backup(backup)
        return False
    if created.returncode != 0 or python_version([str(PYTHON_VENV)]) not in SUPPORTED:
        say('[ERROR] .venv creation did not yield a supported Python interpreter.')
        restore_venv_backup(backup)
        return False
    return True


def ensure_imports() -> bool:
    result = run([str(PYTHON_VENV), '-c', IMPORT_TEST], timeout=90)
    return result.returncode == 0


def dependency_install_args() -> list[str]:
    """Pip arguments for the dependency install.

    Prefer the hash-locked lockfile so the install is deterministic and
    hash-verified; fall back to the range-specified requirements.txt when
    the lockfile is absent from the checkout.
    """
    lock = ROOT / 'requirements.lock.txt'
    if lock.is_file():
        return ['-m', 'pip', 'install', '--upgrade', '--require-hashes',
                '-r', str(lock)]
    return ['-m', 'pip', 'install', '--upgrade', '-r', str(ROOT / 'requirements.txt')]


def install_dependencies() -> bool:
    for args in (['-m', 'pip', 'install', '--upgrade', 'pip'],
                 dependency_install_args()):
        say(f'[*] Running: .venv\\Scripts\\python.exe {" ".join(args)}')
        try:
            result = run([str(PYTHON_VENV), *args], timeout=900)
        except (OSError, subprocess.TimeoutExpired) as exc:
            say(f'[ERROR] Package installation interrupted: {exc}')
            return False
        if result.returncode != 0:
            say(f'[ERROR] pip failed with exit code {result.returncode}.')
            return False
    say('[*] Checking all Python imports (including internal src/ modules)...')
    if ensure_imports():
        return True
    # Reinstalling requests cannot repair a missing local module such as penx_app.scanners.tools.
    # Only touch third-party HTTP packages if their own imports are broken.
    say('[WARN] Import check failed. Checking HTTP dependencies independently...')
    try:
        http_check = run([str(PYTHON_VENV), '-c', HTTP_IMPORT_TEST], timeout=45)
        if http_check.returncode == 0:
            say('[ERROR] HTTP packages are healthy. A different import failed above.')
            say('[ERROR] Verify the repository src/ directory and installed dependencies.')
            say('[ERROR] No packages were reinstalled and no scanners were started.')
            return False
        say('[WARN] HTTP imports failed; repairing requests and charset-normalizer...')
        result = run([str(PYTHON_VENV), '-m', 'pip', 'install', '--no-cache-dir',
                      '--force-reinstall', 'requests>=2.32,<3', 'charset-normalizer>=3.4,<4'],
                     timeout=600)
        if result.returncode == 0 and ensure_imports():
            return True
    except (OSError, subprocess.TimeoutExpired) as exc:
        say(f'[ERROR] Package repair failed: {exc}')
    say('[ERROR] PenX import validation failed. No scanner installation was started.')
    return False


def main() -> int:
    say('==============================================')
    say(' PenX - Windows Python environment validation')
    say('==============================================')
    say(f'[*] Bootstrap Python: {sys.version.split()[0]}')
    if os.name != 'nt':
        say('[ERROR] This installer is intended for Windows only.')
        return 1
    current = python_version([str(PYTHON_VENV)]) if PYTHON_VENV.is_file() else None
    python: list[str] | None
    if current in SUPPORTED:
        say('[OK] Existing .venv uses a supported Python version.')
        python = [str(PYTHON_VENV)]
    else:
        python = find_supported_python()
        if not python:
            if not install_python_with_winget():
                return 1
            python = find_supported_python()
        if not python:
            say('[ERROR] Python 3.13 could not be found even after installation.')
            say('        Close this window, reopen it and run install-windows.bat again.')
            return 1
        version = python_version(python)
        if version not in SUPPORTED:
            say('[ERROR] Candidate Python version changed during setup.')
            return 1
        say(f'[OK] Selected Python {version[0]}.{version[1]}: {" ".join(python)}')
    try:
        backups: list[Path] = []
        if not ensure_venv(python, backups=backups):
            return 1
        if not install_dependencies():
            if backups:
                restore_venv_backup(backups[-1])
            return 1
    except (OSError, PermissionError) as exc:
        say(f'[ERROR] Virtual environment setup failed: {exc}')
        return 1
    say('[OK] PenX Python environment verified. Existing .env and data/ preserved.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
