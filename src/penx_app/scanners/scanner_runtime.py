"""Locate Ruby/Perl even when winget updated PATH after this process started.

No external dependencies: also imported by the standalone scanner installer.
"""
from __future__ import annotations

import os
from pathlib import Path
import shutil

from penx_app.app_paths import APP_ROOT
ROOT = APP_ROOT
VENDOR = ROOT / 'vendor'
WHATWEB_SCRIPT = VENDOR / 'whatweb' / 'whatweb'
NIKTO_SCRIPT = VENDOR / 'nikto' / 'program' / 'nikto.pl'


def find_runtime(tool: str) -> str | None:
    """Return an existing Ruby/Perl interpreter; never execute candidates."""
    if tool not in ('ruby', 'perl'):
        raise ValueError('Only ruby and perl are supported')
    extra = os.environ.get(f'PENX_{tool.upper()}_PATH', os.environ.get(f'METATRON_{tool.upper()}_PATH', '')).strip().strip('"')
    if extra and Path(extra).is_file():
        return str(Path(extra).resolve())
    hit = shutil.which(tool)
    if hit:
        return hit
    if os.name != 'nt':
        return None

    exe = tool + '.exe'
    drive = Path(os.environ.get('SystemDrive', 'C:') + os.sep)
    bases = [drive, Path(os.environ.get('LOCALAPPDATA', str(drive / 'Users'))),
             Path(os.environ.get('ProgramFiles', str(drive / 'Program Files'))),
             Path(os.environ.get('ProgramFiles(x86)', str(drive / 'Program Files (x86)')))]
    candidates = []
    if tool == 'perl':
        candidates.extend((drive / 'Strawberry' / 'perl' / 'bin' / exe,
                           drive / 'Strawberry' / 'c' / 'bin' / exe))
        for base in bases[1:]:
            candidates.extend((base / 'Strawberry' / 'perl' / 'bin' / exe,
                               base / 'Strawberry Perl' / 'perl' / 'bin' / exe))
    else:
        for base in bases:
            # RubyInstaller generally installs in C:\Ruby34-x64\bin.
            candidates.extend(sorted(base.glob('Ruby*' + '/bin/' + exe), reverse=True))
            candidates.extend(sorted((base / 'Programs').glob('Ruby*' + '/bin/' + exe), reverse=True))
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    return None


def executable_env(interpreter: str) -> dict[str, str]:
    """Include a newly installed interpreter's bin directory in child PATH."""
    env = os.environ.copy()
    env['PATH'] = str(Path(interpreter).resolve().parent) + os.pathsep + env.get('PATH', '')
    return env


def find_ruby_command(ruby: str, command: str) -> str | None:
    """Locate `bundle.bat` or `gem.cmd` installed alongside Ruby."""
    bin_dir = Path(ruby).resolve().parent
    for suffix in ('.bat', '.cmd', '.exe', ''):
        path = bin_dir / (command + suffix)
        if path.is_file():
            return str(path)
    return shutil.which(command, path=executable_env(ruby)['PATH'])


def find_nmap(override: str = '') -> str | None:
    """Find a native Nmap installation independently of the current PATH."""
    if override:
        candidate = Path(override.strip().strip('"'))
        if candidate.is_file():
            return str(candidate)
    hit = shutil.which('nmap')
    if hit:
        return hit
    if os.name != 'nt':
        return None
    for base in (os.environ.get('ProgramFiles', ''), os.environ.get('ProgramFiles(x86)', ''),
                 os.environ.get('LOCALAPPDATA', '')):
        if base and (Path(base) / 'Nmap' / 'nmap.exe').is_file():
            return str(Path(base) / 'Nmap' / 'nmap.exe')
    return None


def npcap_present() -> bool:
    """Check for the driver installed by the official Nmap Windows installer."""
    if os.name != 'nt':
        return False
    root = Path(os.environ.get('SystemRoot', 'C:\\Windows'))
    return any(p.is_file() for p in (root / 'System32' / 'drivers' / 'npcap.sys',
                                     root / 'Sysnative' / 'drivers' / 'npcap.sys'))
