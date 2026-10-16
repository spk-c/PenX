#!/usr/bin/env python3
"""Install genuine Nmap/Npcap, WhatWeb, and Nikto for PenX on Windows.

Runs only from explicit setup commands or after consent in the EXE first-run wizard.
Ruby/Perl are installed via Windows package manager (winget); scanner sources come
from official GitHub HTTPS archives, never untrusted mirrors or execute-on-download.
"""
from __future__ import annotations

import argparse
import io
import hashlib
import re
import html
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tempfile
from urllib.request import Request, urlopen
from urllib.parse import urljoin, urlsplit
import zipfile
import requests

from penx_app.app_paths import APP_ROOT
from penx_app.scanners.scanner_runtime import VENDOR, WHATWEB_SCRIPT, NIKTO_SCRIPT, find_runtime, executable_env, find_ruby_command, find_nmap, npcap_present
from penx_app.setup.native_scanner_setup import SOURCES as NATIVE_SOURCES, download_verified_exe, install_nuclei_templates
from penx_app.scanners.native_web_scanners import find_native, nuclei_templates, template_install_directory

try:
    from dotenv import load_dotenv
    load_dotenv(dotenv_path=APP_ROOT / '.env')
except ImportError:
    pass  # Allows archive/installer regression tests with stdlib only.

# Freeze upstream source trees to verified Git commits rather than mutable
# branch/tag aliases. Review and update these SHAs deliberately when upgrading.
# HTTPS transport is still required; GitHub archive ZIPs have no official
# independently published SHA256 manifest, so this is NOT a digest check.
WHATWEB_COMMIT = 'd279d93042d034f3fd29d5a893d44ccc0595d3f8'  # WhatWeb v0.6.4
NIKTO_COMMIT = '312645d873478a77986627ab1fc8cffe595e85d4'  # 2026-08-15
WHATWEB_URL = f'https://github.com/urbanadventurer/WhatWeb/archive/{WHATWEB_COMMIT}.zip'
NIKTO_URL = f'https://github.com/sullo/nikto/archive/{NIKTO_COMMIT}.zip'
PACKAGES = {'ruby': 'RubyInstallerTeam.RubyWithDevKit.3.4',
            'perl': 'StrawberryPerl.StrawberryPerl'}
MAX_ARCHIVE = 60 * 1024 * 1024
MAX_EXTRACTED = 350 * 1024 * 1024
NMAP_DOWNLOAD_PAGE = "https://nmap.org/download.html"
MAX_NMAP_INSTALLER = 130 * 1024 * 1024


def say(text: str) -> None:
    print(text, flush=True)


def invoke(argv: list[str], *, cwd: Path | None = None, env: dict | None = None,
           timeout: int = 300) -> bool:
    """No shell expansion; show status, not credentials or arbitrary script output."""
    say('  > ' + ' '.join('"' + a + '"' if ' ' in a else a for a in argv))
    try:
        result = subprocess.run(argv, cwd=str(cwd) if cwd else None, env=env,
                                timeout=timeout, check=False)
        if result.returncode:
            say(f'  [WARN] Exit status: {result.returncode}')
            return False
        return True
    except (OSError, subprocess.TimeoutExpired) as exc:
        say(f'  [WARN] Unable to run command: {exc}')
        return False


def ensure_runtime(name: str, *, no_winget: bool = False) -> str | None:
    path = find_runtime(name)
    if path:
        say(f'[OK] {name}: {path}')
        return path
    winget = shutil.which('winget')
    if no_winget or os.name != 'nt' or not winget:
        say(f'[WARN] {name} missing. Install via winget: winget install --id {PACKAGES[name]} -e')
        return None
    say(f'[*] Installing {name} via winget (UAC approval may be required)...')
    invoke([winget, 'install', '--id', PACKAGES[name], '--exact',
            '--accept-package-agreements', '--accept-source-agreements'], timeout=1200)
    path = find_runtime(name)
    if not path:
        say(f'[WARN] Could not locate {name} after winget. Restart the terminal if newly installed.')
    else:
        say(f'[OK] {name}: {path}')
    return path


def _validate_download_origin(response, allowed_hosts: set[str]) -> None:
    """Reject an unexpected redirect or HTTPS-to-HTTP downgrade.

    GitHub archive endpoints legitimately redirect to codeload.github.com.
    urllib HTTPResponse exposes geturl(); lightweight offline mocks may not.
    """
    geturl = getattr(response, 'geturl', None)
    if not callable(geturl):
        return
    actual = urlsplit(str(geturl()))
    if actual.scheme != 'https' or actual.hostname not in allowed_hosts:
        raise ValueError('Installer download redirected outside allowed HTTPS publisher hosts')


def download_archive(url: str) -> bytes:
    """Only bounded HTTPS downloads from the two explicitly supported repositories."""
    if url not in (WHATWEB_URL, NIKTO_URL):
        raise ValueError('Unknown download source')
    request = Request(url, headers={'User-Agent': 'PenX-Windows-Installer/1.0'})
    with urlopen(request, timeout=90) as response:
        _validate_download_origin(response, {'github.com', 'codeload.github.com'})
        data = response.read(MAX_ARCHIVE + 1)
    if len(data) > MAX_ARCHIVE:
        raise ValueError('Archive exceeds size limit')
    if not zipfile.is_zipfile(io.BytesIO(data)):
        raise ValueError('Downloaded content is not a ZIP archive')
    return data


def safe_unzip(contents: bytes, dest: Path) -> None:
    """Reject path traversal, links, and zip bombs; strip repository root folder."""
    total = 0
    with zipfile.ZipFile(io.BytesIO(contents)) as archive:
        infos = archive.infolist()
        if len(infos) > 30000:
            raise ValueError('Unusually large number of archive entries')
        for member in infos:
            parts = PurePosixPath(member.filename.replace('\\', '/')).parts
            if len(parts) < 2 or any(x in ('', '.', '..') for x in parts) or ':' in member.filename:
                # A single entry for the archive root is fine.
                if len(parts) == 1 and member.is_dir():
                    continue
                raise ValueError(f'Unsafe archive entry: {member.filename}')
            # Symlinks in untrusted archives are deliberately unsupported.
            mode = (member.external_attr >> 16) & 0o170000
            if mode == 0o120000:
                raise ValueError(f'Symlink not permitted: {member.filename}')
            rel = Path(*parts[1:])
            if not rel.parts:
                continue
            total += member.file_size
            if total > MAX_EXTRACTED:
                raise ValueError('Extracted contents exceed size limit')
            dest_file = dest / rel
            if member.is_dir():
                dest_file.mkdir(parents=True, exist_ok=True)
            else:
                dest_file.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(member) as inp, dest_file.open('wb') as out:
                    shutil.copyfileobj(inp, out)


def ensure_source(label: str, url: str, folder: Path, marker: Path) -> bool:
    if marker.is_file():
        say(f'[OK] {label} already downloaded: {marker}')
        return True
    say(f'[*] Downloading {label} from official GitHub repository...')
    try:
        VENDOR.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='.download-', dir=VENDOR) as tmp:
            staging = Path(tmp) / 'source'
            staging.mkdir()
            safe_unzip(download_archive(url), staging)
            # Require the actual expected entrypoint before moving it to place.
            if not (staging / marker.relative_to(folder)).is_file():
                raise ValueError(f'{label} entrypoint missing from source archive')
            if folder.exists():
                # Avoid destroying user modifications or partial source installs.
                raise ValueError(f'{folder} already exists but is incomplete. Move it aside and retry.')
            staging.rename(folder)
        say(f'[OK] {label} source ready: {marker}')
        return True
    except (OSError, ValueError, zipfile.BadZipFile, TimeoutError) as exc:
        say(f'[FAIL] Could not download/extract {label}: {exc}')
        return False


def setup_whatweb(ruby: str | None) -> bool:
    if not ruby:
        say('[WARN] WhatWeb needs Ruby; download will still be attempted.')
    if not ensure_source('WhatWeb v0.6.4', WHATWEB_URL, WHATWEB_SCRIPT.parent, WHATWEB_SCRIPT):
        return False
    if not ruby:
        return False
    env = executable_env(ruby)
    gem = find_ruby_command(ruby, 'gem')
    bundle = find_ruby_command(ruby, 'bundle')
    if not bundle and gem:
        say('[*] Installing Ruby Bundler...')
        invoke([gem, 'install', 'bundler', '--no-document'], env=env, timeout=300)
        bundle = find_ruby_command(ruby, 'bundle')
    if not bundle:
        say('[FAIL] Bundler not found; check the RubyInstaller setup.')
        return False
    # Exclude optional packages + test/development gems; keeps install small.
    invoke([bundle, 'config', 'set', '--local', 'without', 'test development mongo rchardet'],
           cwd=WHATWEB_SCRIPT.parent, env=env, timeout=90)
    if not invoke([bundle, 'install'], cwd=WHATWEB_SCRIPT.parent, env=env, timeout=600):
        say('[WARN] WhatWeb dependencies incomplete. Re-run install-windows.bat.')
        return False
    say('[*] Checking genuine WhatWeb without scanning any host...')
    ok = invoke([ruby, str(WHATWEB_SCRIPT), '--version'], cwd=WHATWEB_SCRIPT.parent, env=env, timeout=45)
    say('[OK] WhatWeb ready' if ok else '[WARN] WhatWeb dependency check failed')
    return ok


def nikto_module_available(perl: str, module: str = 'XML::Writer') -> bool:
    """Check a Perl dependency without performing any network activity."""
    if not re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*(?:::[A-Za-z_][A-Za-z_0-9]*)*', module):
        raise ValueError('Invalid Perl module name')
    try:
        result = subprocess.run([perl, '-M' + module, '-e', '1'], cwd=str(NIKTO_SCRIPT.parent),
                                env=executable_env(perl), capture_output=True,
                                text=True, timeout=20, check=False)
        return result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def ensure_nikto_module(perl: str) -> bool:
    """Install Nikto's required XML writer only during explicit scanner setup."""
    if nikto_module_available(perl):
        return True
    say('[WARN] Nikto requires missing Perl module XML::Writer.')
    env = executable_env(perl)
    env['PERL_MM_USE_DEFAULT'] = '1'
    env['AUTOMATED_TESTING'] = '1'
    say('[*] Installing XML::Writer from CPAN for the selected Perl runtime...')
    if not invoke([perl, '-MCPAN', '-e', "CPAN::Shell->install('XML::Writer')"],
                  cwd=NIKTO_SCRIPT.parent, env=env, timeout=600):
        say('[WARN] CPAN installation failed. Retry setup or install XML::Writer manually.')
        return False
    if not nikto_module_available(perl):
        say('[WARN] XML::Writer is still unavailable in the selected Perl environment.')
        return False
    return True


def setup_nikto(perl: str | None) -> bool:
    if not ensure_source('Nikto (upstream main)', NIKTO_URL, NIKTO_SCRIPT.parent.parent, NIKTO_SCRIPT):
        return False
    if not perl:
        say('[WARN] Nikto source downloaded, but Perl interpreter is missing.')
        return False
    if not ensure_nikto_module(perl):
        return False
    say('[*] Checking Nikto startup without scanning any host...')
    env = executable_env(perl)
    syntax_ok = invoke([perl, '-c', str(NIKTO_SCRIPT)], cwd=NIKTO_SCRIPT.parent, env=env, timeout=60)
    startup_ok = syntax_ok and invoke([perl, str(NIKTO_SCRIPT), '-Version'],
                                      cwd=NIKTO_SCRIPT.parent, env=env, timeout=60)
    say('[OK] Nikto ready' if startup_ok else '[WARN] Nikto startup failed; check Perl dependencies')
    return startup_ok



def official_nmap_installer_url(page: str) -> str:
    """Extract the current Windows installer hosted on nmap.org, never a mirror."""
    matches = re.findall(r'nmap-[0-9]+(?:\.[0-9]+)+-setup\.exe', html.unescape(page), re.I)
    if not matches:
        raise ValueError('Official Nmap download page contains no Windows installer link')
    # The stable self-installer is listed before beta/testing releases.
    filename = matches[0]
    return 'https://nmap.org/dist/' + filename


def fetch_nmap_installer_url() -> str:
    with urlopen(Request(NMAP_DOWNLOAD_PAGE, headers={'User-Agent':'PenX-Windows-Installer/2.0'}), timeout=45) as response:
        _validate_download_origin(response, {'nmap.org', 'www.nmap.org'})
        source = response.read(2_000_001)
        if len(source) > 2_000_000:
            raise ValueError('Unusually large Nmap download page')
    return official_nmap_installer_url(source.decode('utf-8', errors='replace'))


def fetch_official_exe(url: str, location: Path) -> None:
    """Download only the official Nmap HTTPS executable, with a strict size cap."""
    info = urlsplit(url)
    if (info.scheme != 'https' or info.hostname != 'nmap.org' or
            not re.fullmatch(r'/dist/nmap-[0-9]+(?:\.[0-9]+)+-setup\.exe', info.path) or
            info.query or info.fragment):
        raise ValueError('Refusing Nmap download outside the official domain')
    with urlopen(Request(url, headers={'User-Agent':'PenX-Windows-Installer/2.0'}), timeout=120) as response:
        _validate_download_origin(response, {'nmap.org', 'www.nmap.org'})
        with location.open('wb') as output:
            total = 0
            while True:
                buf = response.read(1024 * 1024)
                if not buf:
                    break
                total += len(buf)
                if total > MAX_NMAP_INSTALLER:
                    raise ValueError('Nmap installer exceeds allowed size')
                output.write(buf)
    if location.stat().st_size < 1_000_000 or location.open('rb').read(2) != b'MZ':
        raise ValueError('Nmap download is not a plausible Windows installer')


def verify_nmap_sha256(installer: Path, download_url: str) -> bool:
    """Verify the executable against nmap.org's official SHA-256 digest file.

    This also supports official installers without an Authenticode signature.
    The expected digest is fetched from the same HTTPS publisher, not a mirror.
    """
    name = Path(urlsplit(download_url).path).name
    digest_url = f'https://nmap.org/dist/sigs/{name}.digest.txt'
    try:
        with urlopen(Request(digest_url, headers={'User-Agent':'PenX-Windows-Installer/2.0'}), timeout=45) as response:
            _validate_download_origin(response, {'nmap.org', 'www.nmap.org'})
            source = response.read(4097)
            if len(source) > 4096:
                raise ValueError('Unusually large digest file')
        text = source.decode('ascii')
        if f'{name}: SHA256' not in text and not re.search(re.escape(name) + r':\s+SHA256', text):
            raise ValueError('SHA256 digest does not name the expected installer')
        digest_lines = text.split('SHA256 =', 1)[1].splitlines()
        digest_parts = [digest_lines[0]]
        for following in digest_lines[1:]:
            if following.startswith((' ', '\t')) and re.fullmatch(r'[0-9a-fA-F\s]+', following):
                digest_parts.append(following)
            else:
                break
        expected = ''.join(re.findall(r'[0-9a-fA-F]+', ' '.join(digest_parts))).lower()
        if not re.fullmatch(r'[0-9a-f]{64}', expected):
            raise ValueError('Malformed SHA256 digest')
        sha = hashlib.sha256()
        with installer.open('rb') as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b''):
                sha.update(block)
        if sha.hexdigest() == expected:
            say('[OK] Nmap SHA256 matches the official nmap.org digest')
            return True
        say('[FAIL] Nmap installer SHA256 mismatch')
        return False
    except (OSError, UnicodeError, ValueError, TimeoutError, IndexError) as exc:
        say(f'[WARN] Cannot verify official Nmap checksum: {exc}')
        return False


def setup_nmap(*, no_download: bool = False) -> bool:
    """Install current official Windows Nmap; its wizard includes Npcap."""
    from penx_app.config import NMAP_PATH
    existing = find_nmap(NMAP_PATH)
    if existing and (npcap_present() or os.name != 'nt'):
        say(f'[OK] Nmap: {existing}; Npcap ' + ('detected' if npcap_present() else 'not applicable'))
        return True
    if existing:
        say('[WARN] Nmap is installed but Npcap driver was not found.')
    if no_download or os.name != 'nt':
        say('[WARN] Nmap / Npcap setup requires Windows. Official installer: https://nmap.org/download.html')
        return False
    say('[*] Downloading current Nmap installer from nmap.org (includes Npcap selection)...')
    try:
        url = fetch_nmap_installer_url()
        with tempfile.TemporaryDirectory(prefix='penx-nmap-') as tmp:
            installer = Path(tmp) / Path(urlsplit(url).path).name
            fetch_official_exe(url, installer)
            if not verify_nmap_sha256(installer, url):
                say('[FAIL] Will not execute unverified installer. Install manually from https://nmap.org/download.html')
                return False
            say('[*] Opening Nmap setup. Keep the Npcap option selected and finish the installation wizard.')
            # The official interactive installer is intentional: Npcap requires
            # a driver installation and Windows admin consent.
            if not invoke([str(installer)], timeout=1800):
                return False
    except (OSError, ValueError, TimeoutError) as exc:
        say(f'[FAIL] Nmap setup could not complete: {exc}')
        return False
    existing = find_nmap(NMAP_PATH)
    ready = bool(existing and npcap_present())
    say('[OK] Nmap and Npcap detected' if ready else '[WARN] Nmap or Npcap not detected after setup. Check the installer options.')
    return ready


def setup_native_scanners() -> dict[str, bool]:
    """Install missing Nuclei/httpx/ffuf/Subfinder/Katana after setup consent.

    The BAT or first-run wizard already initiates/authorizes setup, so no
    second input prompt is needed. Official GitHub release assets are
    SHA256-verified by download_verified_exe; no binary runs during setup.
    """
    results: dict[str, bool] = {}
    for name in NATIVE_SOURCES:
        existing = find_native(name)
        if existing:
            say(f'[OK] {name}: {existing}')
            results[name] = True
            continue
        say(f'[*] Installing {name} (verified Windows x64 release)...')
        try:
            installed = download_verified_exe(name)
            # Respect an explicit custom executable override, including
            # a broken override that could hide an installed vendor binary.
            detected = find_native(name)
            if not detected:
                raise ValueError(f'{installed} was downloaded but PenX cannot locate it. '
                                 f'Check PENX_{name.upper()}_PATH.')
            say(f'[OK] {name} installed: {detected}')
            results[name] = True
        except (OSError, ValueError, TypeError, KeyError,
                zipfile.BadZipFile, requests.RequestException) as exc:
            say(f'[FAIL] {name}: {exc}')
            results[name] = False
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description='Install Nmap/Npcap, WhatWeb, Nikto, Nuclei, httpx, ffuf, Subfinder and Katana for Windows PenX')
    parser.add_argument('--no-winget', action='store_true', help='Do not install Ruby or Perl')
    parser.add_argument('--skip-nmap', action='store_true', help='Do not install Nmap/Npcap')
    parser.add_argument('--skip-native', action='store_true',
                        help='Skip optional Nuclei, httpx, ffuf, Subfinder and Katana installation')
    args = parser.parse_args(argv)
    say('PenX Windows: Nmap/Npcap, WhatWeb, Nikto, Nuclei, httpx, ffuf, Subfinder and Katana setup (internet required)')
    if os.name != 'nt':
        say('[INFO] This setup is intended for Windows. Download/test mode on other OS.')
    nmap_ok = setup_nmap(no_download=args.skip_nmap)
    ruby = ensure_runtime('ruby', no_winget=args.no_winget)
    perl = ensure_runtime('perl', no_winget=args.no_winget)
    whatweb_ok = setup_whatweb(ruby)
    nikto_ok = setup_nikto(perl)
    native = {} if args.skip_native else setup_native_scanners()
    # Explicit BAT / first-run setup consent also covers fetching the official
    # template inventory; live scans must never update it automatically.
    templates_ready = True
    if not args.skip_native and native.get("nuclei") and nuclei_templates() is None:
        executable = find_native("nuclei")
        if executable:
            say("[*] Installing Nuclei templates through the official updater...")
            templates_ready = install_nuclei_templates(executable, template_install_directory())
        else:
            templates_ready = False
    say('\nNmap/Npcap: ' + ('READY' if nmap_ok else 'INCOMPLETE'))
    say('WhatWeb:    ' + ('READY' if whatweb_ok else 'INCOMPLETE'))
    say('Nikto:      ' + ('READY' if nikto_ok else 'INCOMPLETE'))
    if not args.skip_native:
        say("Nuclei templates: " + ("READY" if templates_ready else "INCOMPLETE"))
    for name in NATIVE_SOURCES:
        say(f'{name}: ' + ('SKIPPED' if args.skip_native
              else 'READY' if native.get(name) else 'INCOMPLETE'))
    return 0 if (nmap_ok and whatweb_ok and nikto_ok
                 and (args.skip_native or (all(native.values()) and templates_ready))) else 1


if __name__ == '__main__':
    sys.exit(main())
