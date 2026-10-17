#!/usr/bin/env python3
"""PenX reconnaissance: Windows-native adapters with portable Python fallbacks.

External scanners are never auto-installed or silently replaced with equivalent-
looking results. Fallback Python implementations clearly identify themselves.
Use only on networks or systems you have permission to assess.
"""
from __future__ import annotations

from enum import Enum as Enum
import ipaddress
import os
from pathlib import Path
import re
import shlex
import queue as queue
import threading as threading
import time as time
import shutil
import subprocess as subprocess
import tempfile
from urllib.parse import urlsplit

import requests
from penx_app.runtime_options import live_output as live_output
from penx_app.domain.scan_models import ScannerResult as ScannerResult, ScanResult as ScanResult, ReconText as ReconText
from penx_app.scanners.scan_results import format_recon_for_llm, recon_has_evidence as recon_has_evidence
from bs4 import BeautifulSoup

from penx_app.config import NMAP_PATH, NIKTO_PATH, WHATWEB_PATH
from penx_app.scanners.scanner_targets import normalize_host, normalize_web_target, target_urls, MAX_CIDR_ADDRESSES
from penx_app.scanners.scanner_runtime import find_runtime, executable_env, find_nmap, npcap_present
from penx_app.scanners.native_web_scanners import find_native, web_endpoint, nuclei_args, httpx_args, ffuf_args, ffuf_words, nuclei_templates, subfinder_args, katana_args, summarize_output
from penx_app.scanners.endpoint_inventory import EndpointInventory, load_inventory, save_inventory


from penx_app.domain.scan_models import ScannerOutput


def _process_outcome(value: str) -> ScannerOutput:
    """Accept legacy mocked tool output without mistaking errors for evidence."""
    if isinstance(value, ScannerOutput):
        return value
    # Legacy mocked adapters may return plain text. An arbitrary object
    # representation (None, False, list, dict, repr(...)) cannot attest that
    # a scanner actually ran successfully.
    if not isinstance(value, str):
        return ScannerOutput(
            f"[!] Unsupported scanner output type: {type(value).__name__}",
            status="FAILED", evidence=False,
        )
    text = value
    if text.lstrip().startswith("[!] Timed out"):
        return ScannerOutput(text, status="PARTIAL", evidence=False)
    failed = text.lstrip().startswith(("[!", "[EXIT CODE", "[ERROR]", "Traceback "))
    return ScannerOutput(text, status="FAILED" if failed else "COMPLETE",
                         evidence=bool(text.strip()) and not failed)



def _scanner_timeout(name: str, default: int) -> int:
    """Separate bounded adapter deadlines from the local-LLM timeout."""
    try:
        value = int(os.getenv("PENX_" + name.upper() + "_TIMEOUT", str(default)))
    except ValueError:
        value = default
    return max(30, min(value, 900))


def _host(target: str) -> str:
    """Legacy scanner API; validation lives in scanner_targets."""
    return normalize_host(target, max_addresses=MAX_CIDR_ADDRESSES)



def _executable(tool: str, override: str = '') -> str | None:
    if override and Path(override).is_file():
        return str(Path(override))
    found = shutil.which(tool)
    if found:
        return found
    if tool == 'nmap':
        return find_nmap(override)
    return None


def tool_status() -> dict[str, str]:
    ruby = find_runtime('ruby')
    perl = find_runtime('perl')
    whatweb = Path(WHATWEB_PATH).is_file() if WHATWEB_PATH else False
    nikto = Path(NIKTO_PATH).is_file() if NIKTO_PATH else False
    return {
        'nmap': (_executable('nmap', NMAP_PATH) or 'not installed') +
                (' (Npcap detected)' if npcap_present() else ' (Npcap not detected; some scan types may fail)' if os.name == 'nt' else ''),
        'nikto': f'installed: {NIKTO_PATH} (Perl: {perl})' if nikto and perl
                 else 'missing Perl' if nikto else 'not installed (run install-windows.bat)',
        'whatweb': f'installed: {WHATWEB_PATH} (Ruby: {ruby})' if whatweb and ruby
                   else 'missing Ruby; Python fallback only' if whatweb
                   else 'not installed; limited Python fallback',
        'whois': 'Python WHOIS',
        'http': 'Python requests',
        'dns': 'dnspython',
        'nuclei': find_native('nuclei') or 'not installed (Windows native scanner)',
        'httpx': find_native('httpx') or 'not installed (ProjectDiscovery HTTPx)',
        'ffuf': find_native('ffuf') or 'not installed (Windows native scanner)',
    }


from penx_app.scanners.process_runner import _run_tool_live as _run_tool_live


from penx_app.scanners.process_runner import run_tool


def _run_external(command, *, timeout, cancel_event=None, **kwargs):
    """Retain legacy subprocess mocks when the caller has no cancellation token."""
    if cancel_event is not None:
        kwargs["cancel_event"] = cancel_event
    return run_tool(command, timeout=timeout, **kwargs)


def _cancelled_before_start(cancel_event) -> ScannerOutput | None:
    if cancel_event is not None and cancel_event.is_set():
        return ScannerOutput("[!] Scanner cancelled before start.", status="PARTIAL",
                             evidence=False, diagnostics="Caller requested scanner cancellation")
    return None


def _cancelled_after_io(cancel_event) -> ScannerOutput | None:
    """Do not promote results returned after a caller cancelled blocking I/O."""
    if cancel_event is not None and cancel_event.is_set():
        return ScannerOutput(
            "[!] Scanner cancelled; in-flight network output is not completed evidence.",
            status="PARTIAL", evidence=False,
            diagnostics="Caller requested scanner cancellation during network I/O",
        )
    return None


def run_nmap(target: str, *, cancel_event=None) -> str:
    cancelled = _cancelled_before_start(cancel_event)
    if cancelled is not None:
        return cancelled
    try:
        host = _host(target)
    except ValueError as exc:
        return ScannerOutput(f'[!] Nmap: {exc}', status="FAILED", evidence=False)
    path = _executable('nmap', NMAP_PATH)
    if not path:
        return ScannerOutput(
            '[!] Nmap is not installed. On Windows install Nmap from '
            'https://nmap.org/download.html and restart this program. '
            'Or set PENX_NMAP_PATH.', status="FAILED", evidence=False)
    print(f'  [*] nmap -sV -sC -T4 --open {host}')
    # Preserve the normal Nmap output and capture structured CPE/version data
    # in a temporary XML report for the CVE discovery engine.
    with tempfile.TemporaryDirectory(prefix='penx_nmap_') as temp:
        xml_file = Path(temp) / 'nmap.xml'
        live = os.getenv("PENX_LIVE_OUTPUT", "0").lower() in ("1", "on", "true", "yes")
        args = [path, '-sV', '-sC', '-T4', '--open']
        if live:
            args.extend(['--stats-every', '10s', '-v'])
        args.extend(['-oX', str(xml_file), host])
        # Allow slow authorized targets more time without an unbounded scan.
        try:
            timeout = int(os.getenv('PENX_NMAP_TIMEOUT', '180'))
        except ValueError:
            timeout = 180
        timeout = max(30, min(timeout, 900))
        outcome = _process_outcome(_run_external(args, timeout=timeout, cancel_event=cancel_event))
        report = str(outcome)
        try:
            if xml_file.is_file() and xml_file.stat().st_size <= 2_000_000:
                xml = xml_file.read_text(encoding='utf-8', errors='replace')
                if '<nmaprun' in xml and '</nmaprun>' in xml:
                    report += '\n[NMAP STRUCTURED XML]\n' + xml
        except OSError:
            pass
        return ScannerOutput(
            report, status=outcome.status, evidence=outcome.evidence,
            exit_code=outcome.exit_code, diagnostics=outcome.diagnostics,
        )


def run_whois(target: str, *, cancel_event=None) -> str:
    cancelled = _cancelled_before_start(cancel_event)
    if cancelled is not None:
        return cancelled
    try:
        host = _host(target)
    except ValueError as exc:
        return ScannerOutput(f'[!] WHOIS: {exc}', status="FAILED", evidence=False)
    if '/' in host:
        return ScannerOutput(
            '[!] Python WHOIS currently supports domains, not IP/CIDR owner lookups.',
            status="FAILED", evidence=False)
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass  # Domain name, so continue with registry WHOIS.
    else:
        return ScannerOutput(
            '[!] Python WHOIS currently supports domains, not IP owner lookups.',
            status="FAILED", evidence=False)
    try:
        import whois
    except ImportError:
        return ScannerOutput(
            '[!] Missing python-whois. Run: python -m pip install python-whois',
            status="FAILED", evidence=False)
    try:
        result = whois.whois(host)
        cancelled = _cancelled_after_io(cancel_event)
        if cancelled is not None:
            return cancelled
        details = '\n'.join(f'{k}: {v}' for k, v in dict(result).items() if v)
        return ScannerOutput('[Python WHOIS]\n' + (details or 'No registration details returned.'),
                             status="COMPLETE" if details else "FAILED",
                             evidence=bool(details))
    except Exception as exc:
        cancelled = _cancelled_after_io(cancel_event)
        if cancelled is not None:
            return cancelled
        return ScannerOutput(f'[!] WHOIS lookup failed: {exc}',
                             status="FAILED", evidence=False)




def _web_target(target: str) -> str:
    """Legacy scanner API with injectable host normalization for tests."""
    return normalize_web_target(target, host_resolver=_host)


def run_whatweb(target: str, *, cancel_event=None) -> str:
    cancelled = _cancelled_before_start(cancel_event)
    if cancelled is not None:
        return cancelled
    try:
        host = _web_target(target)
    except ValueError as exc:
        return ScannerOutput(f'[!] Web technology fingerprint: {exc}',
                             status="FAILED", evidence=False)
    timed_out = ''
    try:
        installed_script = bool(WHATWEB_PATH and Path(WHATWEB_PATH).is_file())
    except OSError as exc:
        return ScannerOutput(f'[!] WhatWeb script is inaccessible: {exc}',
                             status='FAILED', evidence=False)
    if installed_script:
        ruby = find_runtime('ruby')
        if ruby:
            result = _process_outcome(_run_external([ruby, WHATWEB_PATH, '-a', '1', host],
                                              timeout=60, cancel_event=cancel_event,
                                              cwd=str(Path(WHATWEB_PATH).parent),
                                              env=executable_env(ruby)))
            if result.status != "PARTIAL" or (cancel_event is not None and cancel_event.is_set()):
                return result
            timed_out = str(result) + '\n'
    exe = _executable('whatweb')
    if exe and not timed_out:
        result = _process_outcome(_run_external([exe, '-a', '1', host], timeout=60, cancel_event=cancel_event))
        if result.status != "PARTIAL" or (cancel_event is not None and cancel_event.is_set()):
            return result
        timed_out = str(result) + '\n'

    lines = ['[Windows Python fingerprint fallback — limited; NOT an actual WhatWeb scan]']
    observed = 0
    for url in _urls(target):
        try:
            response = requests.get(url, timeout=(5, 10), allow_redirects=False,
                                    headers={'User-Agent': 'PenX/Windows'},
                                    stream=True)
            try:
                body = response.raw.read(262144, decode_content=True)
                try:
                    content = body.decode(response.encoding or 'utf-8', errors='replace')
                except LookupError:
                    # Remote Content-Type charset is not trusted.
                    content = body.decode('utf-8', errors='replace')
                soup = BeautifulSoup(content, 'html.parser')
                tech = []
                headers = response.headers
                if headers.get('Server'):
                    tech.append('Server=' + headers['Server'])
                if headers.get('X-Powered-By'):
                    tech.append('X-Powered-By=' + headers['X-Powered-By'])
                meta = soup.find('meta', attrs={'name': re.compile('^generator$', re.I)})
                if meta and meta.get('content'):
                    tech.append('Generator=' + str(meta.get('content')))
                for word, marker in [('WordPress', 'wp-content/'),
                                     ('Drupal', '/sites/default/'),
                                     ('Joomla', '/media/system/'),
                                     ('Shopify', 'cdn.shopify.com'),
                                     ('Next.js', '/_next/')]:
                    if marker in content:
                        tech.append(word + ' (heuristic)')
                lines.append(f'{url} -> HTTP {response.status_code} ({response.url})')
                lines.append('Indicators: ' + (
                    ', '.join(tech) or 'No conclusive technology indicators'))
                observed += 1
            finally:
                response.close()
        except requests.RequestException as exc:
            lines.append(f'{url}: {exc}')
    text = '\n'.join(lines) + ('\n' + timed_out if timed_out else '')
    # This is usable *partial* fingerprint evidence, not a full WhatWeb run.
    return ScannerOutput(text, status="PARTIAL" if observed else "FAILED",
                         evidence=bool(observed))

def _urls(target: str) -> list[str]:
    """Legacy scanner API; no network requests are performed here."""
    return target_urls(target, web_target=_web_target)



def run_curl_headers(target: str, *, cancel_event=None) -> str:
    """Native Python HTTP-header requests; no curl or shell required."""
    cancelled = _cancelled_before_start(cancel_event)
    if cancelled is not None:
        return cancelled
    try:
        urls = _urls(target)
    except ValueError as exc:
        return ScannerOutput(f'[!] HTTP headers: {exc}',
                             status="FAILED", evidence=False)
    lines = []
    observed = 0
    for url in urls:
        cancelled = _cancelled_after_io(cancel_event)
        if cancelled is not None:
            return cancelled
        lines.append(f'[{url} headers — Python requests]')
        try:
            response = requests.head(url, timeout=(5, 10), allow_redirects=False,
                                     headers={'User-Agent': 'PenX/Windows'})
            if response.status_code in (405, 501):
                response.close()
                cancelled = _cancelled_after_io(cancel_event)
                if cancelled is not None:
                    return cancelled
                response = requests.get(url, timeout=(5, 10), allow_redirects=False,
                                        stream=True, headers={'User-Agent': 'PenX/Windows'})
            try:
                lines.append(f'HTTP {response.status_code} -> {response.url}')
                for k, v in response.headers.items():
                    # Never persist live session tokens in raw evidence, AI prompts,
                    # debug files or machine-readable report attachments.
                    if k.casefold() in {"set-cookie", "cookie", "authorization", "proxy-authorization"}:
                        observed_flags = []
                        for label in ("HttpOnly", "Secure", "SameSite=Strict", "SameSite=Lax", "SameSite=None"):
                            if re.search(re.escape(label), str(v), re.I):
                                observed_flags.append(label)
                        safe_value = "[REDACTED]" + ("; observed flags: " + ", ".join(observed_flags) if observed_flags else "")
                        lines.append(f"{k}: {safe_value}")
                    else:
                        lines.append(f"{k}: {v}")
                observed += 1
            finally:
                response.close()
        except requests.exceptions.SSLError as exc:
            lines.append(f'[!] TLS certificate validation failed: {exc}')
        except requests.RequestException as exc:
            lines.append(f'[!] Request failed: {exc}')
        cancelled = _cancelled_after_io(cancel_event)
        if cancelled is not None:
            return cancelled
        lines.append('')
    status = ("COMPLETE" if observed == len(urls) else
              "PARTIAL" if observed else "FAILED")
    return ScannerOutput('\n'.join(lines), status=status, evidence=bool(observed))

def run_dig(target: str, *, cancel_event=None) -> str:
    cancelled = _cancelled_before_start(cancel_event)
    if cancelled is not None:
        return cancelled
    try:
        host = _host(target)
        if '/' in host:
            return ScannerOutput('[!] DNS expects a single domain/IP, not a subnet.',
                                 status="FAILED", evidence=False)
        import dns.resolver
        import dns.exception
    except ImportError:
        return ScannerOutput(
            '[!] Missing dnspython. Run: python -m pip install dnspython',
            status="FAILED", evidence=False)
    except ValueError as exc:
        return ScannerOutput(f'[!] DNS: {exc}', status="FAILED", evidence=False)
    lines = ['[Native Python DNS queries]']
    observed = 0
    failed = 0
    for rrtype in ('A', 'AAAA', 'MX', 'NS', 'TXT'):
        cancelled = _cancelled_after_io(cancel_event)
        if cancelled is not None:
            return cancelled
        try:
            answer = dns.resolver.resolve(host, rrtype, lifetime=8)
            values = [str(rdata) for rdata in answer]
            if values:
                observed += 1
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            values = ['(no record)']
        except dns.exception.DNSException as exc:
            values = [f'(!) {exc}']
            failed += 1
        cancelled = _cancelled_after_io(cancel_event)
        if cancelled is not None:
            return cancelled
        lines.append(f'[{rrtype} Records]\n' + '\n'.join(values))
    status = ("FAILED" if not observed else "PARTIAL" if failed else "COMPLETE")
    return ScannerOutput('\n\n'.join(lines), status=status, evidence=bool(observed))

def run_nikto(target: str, *, cancel_event=None) -> str:
    cancelled = _cancelled_before_start(cancel_event)
    if cancelled is not None:
        return cancelled
    try:
        host = _web_target(target)
    except ValueError as exc:
        return ScannerOutput(f'[!] Nikto: {exc}', status="FAILED", evidence=False)
    # Only bare hostname gets an HTTPS default; preserve explicit endpoints.
    explicit_endpoint = "://" in host or "/" in host or (
        ":" in host and not host.startswith("[")
    )
    if explicit_endpoint:
        nikto_args = ['-h', host, '-nointeractive']
    else:
        nikto_args = ['-ssl', '-port', '443', '-h', host, '-nointeractive']
    script = Path(NIKTO_PATH)
    perl = find_runtime('perl') if NIKTO_PATH else None
    try:
        installed_script = bool(perl and script and script.is_file())
    except OSError as exc:
        return ScannerOutput(f'[!] Nikto script is inaccessible: {exc}',
                             status='FAILED', evidence=False)
    if installed_script and perl is not None:
        print(f'  [*] Nikto (Perl): {host}')
        result = _process_outcome(_run_external([perl, str(script), *nikto_args], timeout=_scanner_timeout("nikto", 300),
                                           cwd=str(script.parent), env=executable_env(perl),
                                           cancel_event=cancel_event))
    else:
        exe = _executable('nikto')
        if not exe:
            return ScannerOutput(
                '[!] Nikto unavailable. Run install-windows.bat to install Strawberry Perl '
                'and the genuine Nikto scanner, or set PENX_NIKTO_PATH manually. '
                'No vulnerability scan was performed.',
                status="FAILED", evidence=False)
        result = _process_outcome(_run_external([exe, *nikto_args], timeout=_scanner_timeout("nikto", 300),
                                             cancel_event=cancel_event))
    # Some Nikto versions return exit 0 despite being unable to connect or load
    # modules. Do not treat a banner by itself as completed vulnerability scanning.
    if re.search(r'(?i)(?:\[FAIL\]\s*Unable to connect|Required module not found|The -port option cannot be used with a full URI)', result):
        return ScannerOutput(str(result), status="FAILED", evidence=False)
    # Nikto can exit normally despite terminating early after TLS errors.
    if re.search(r"(?i)(?:error limit\s*\(\d+\)\s*reached|scan terminated:\s*\d+\s+errors|ssl connect failed)", str(result)):
        return ScannerOutput(str(result), status="PARTIAL", evidence=True)
    return result


def _run_native_web_scanner(scanner: str, target: str, *, cancel_event=None) -> ScannerOutput:
    """Run only the fixed native scanner profile against a validated web origin.

    These tools are manually selected; model-suggested TOOL commands cannot
    launch Nuclei or ffuf and cannot supply scanner flags.
    """
    cancelled = _cancelled_before_start(cancel_event)
    if cancelled is not None:
        return cancelled
    try:
        origin = web_endpoint(target, _web_target)
        executable = find_native(scanner)
        if not executable:
            return ScannerOutput(
                f'[!] {scanner} not installed. Download its official Windows release '
                f'and configure PENX_{scanner.upper()}_PATH or add the EXE to PATH. '
                'No scan was run.', status="FAILED", evidence=False)
        if scanner == 'nuclei':
            templates = nuclei_templates()
            if templates is None:
                return ScannerOutput(
                    "[!] Nuclei templates are not installed. Run PenX.exe --setup-native "
                    "to install templates with consent, or set PENX_NUCLEI_TEMPLATES "
                    "to a vetted local templates directory. No Nuclei scan was run.",
                    status="FAILED", evidence=False)
            args = nuclei_args(executable, origin, templates)
            timeout = _scanner_timeout("nuclei", 240)
        elif scanner == 'httpx':
            args = httpx_args(executable, origin)
            timeout = 45
        elif scanner == 'ffuf':
            # Temporary wordlists are never persisted in user reports.
            words = ffuf_words()
            with tempfile.TemporaryDirectory(prefix='penx_ffuf_') as folder:
                wordlist = Path(folder) / 'paths.txt'
                wordlist.write_text('\n'.join(words) + '\n', encoding='utf-8')
                args = ffuf_args(executable, origin, wordlist)
                result = _run_external(args, timeout=70, cancel_event=cancel_event)
                return _summarize_native_run(scanner, result)
        else:
            raise ValueError('Unsupported native scanner')
        return _summarize_native_run(scanner, _run_external(args, timeout=timeout,
                                                          cancel_event=cancel_event))
    except (ValueError, OSError, UnicodeError) as exc:
        return ScannerOutput(f'[!] {scanner}: {exc}', status="FAILED", evidence=False)


def _summarize_native_run(scanner: str, result: str) -> ScannerOutput:
    outcome = _process_outcome(result)
    if scanner == "ffuf" and "Maximum running time for entire process reached" in str(result):
        # ffuf returns nonzero even after a bounded partial enumeration.
        excerpt, observed = summarize_output("ffuf", str(result))
        return ScannerOutput("[PARTIAL FFUF ENUMERATION: time limit reached]\n" +
                             (excerpt if observed else "No matching paths observed before timeout."),
                             status="PARTIAL", evidence=observed)
    if scanner == "httpx" and "pip install 'httpx[cli]'" in str(result):
        return ScannerOutput(
            "[!] Wrong httpx CLI detected (Python HTTPX). Install ProjectDiscovery httpx "
            "through PenX.exe --setup-native or set PENX_HTTPX_PATH to its executable.",
            status="FAILED", evidence=False)
    if str(result).strip() == '[!] Tool returned no output.':
        # Nuclei/ffuf may successfully return zero JSONL matches. For httpx,
        # silence instead means that no HTTP endpoint could be confirmed.
        summary, _ = summarize_output(scanner, '')
        return ScannerOutput(summary, status="FAILED" if scanner == "httpx" else "COMPLETE",
                             evidence=False)
    if outcome.status != "COMPLETE":
        return ScannerOutput(str(outcome)[:8000], status=outcome.status,
                             evidence=False)
    summary, evidence = summarize_output(scanner, str(outcome))
    if not evidence:
        return ScannerOutput("[!] " + scanner + " emitted no parseable JSONL result. " +
                             str(outcome)[:600], status="FAILED", evidence=False)
    return ScannerOutput(summary, status="COMPLETE", evidence=True)


def run_nuclei(target: str, *, cancel_event=None) -> ScannerOutput:
    return _run_native_web_scanner('nuclei', target, cancel_event=cancel_event)


def run_httpx(target: str, *, cancel_event=None) -> ScannerOutput:
    return _run_native_web_scanner('httpx', target, cancel_event=cancel_event)


def run_ffuf(target: str, *, cancel_event=None) -> ScannerOutput:
    return _run_native_web_scanner('ffuf', target, cancel_event=cancel_event)


def run_subfinder(target: str, *, cancel_event=None) -> ScannerOutput:
    """Passive discovery only; return hostnames, never start scans on discoveries."""
    cancelled = _cancelled_before_start(cancel_event)
    if cancelled is not None:
        return cancelled
    try:
        from urllib.parse import urlsplit
        import json
        origin = web_endpoint(target, _web_target)
        domain = (urlsplit(origin).hostname or "").rstrip(".").lower()
        if not domain or not re.fullmatch(r"[a-z0-9.-]+", domain):
            raise ValueError("Subfinder requires a DNS hostname")
        try:
            ipaddress.ip_address(domain)
            raise ValueError("Subfinder requires a domain, not an IP address")
        except ValueError as exc:
            if str(exc).startswith("Subfinder"):
                raise
        executable = find_native("subfinder")
        if not executable:
            raise ValueError("Subfinder not installed; set PENX_SUBFINDER_PATH")
        outcome = _process_outcome(_run_external(subfinder_args(executable, domain), timeout=135,
                                               cancel_event=cancel_event))
        if str(outcome).strip() == "[!] Tool returned no output.":
            return ScannerOutput("[*] Subfinder completed; no in-scope subdomains discovered.",
                                 status="COMPLETE", evidence=False)
        if outcome.status != "COMPLETE":
            return ScannerOutput(str(outcome)[:2000], status=outcome.status, evidence=False)
        found = set()
        malformed = 0
        valid_rows = 0
        for line in str(outcome).splitlines():
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except ValueError:
                malformed += 1
                continue
            if not isinstance(item, dict) or not isinstance(item.get("host"), str):
                malformed += 1
                continue
            host = item["host"].strip().rstrip(".").lower()
            # Provider JSON is untrusted. Matching a string suffix is not
            # enough: 'bad@.example.test' or embedded controls would otherwise
            # be presented to the model as discovered DNS hostnames.
            try:
                canonical = normalize_host(host)
            except ValueError:
                malformed += 1
                continue
            if not host or canonical != host:
                malformed += 1
                continue
            valid_rows += 1
            if host == domain or host.endswith("." + domain):
                found.add(host)
        if malformed:
            note = f"[!] Subfinder emitted {malformed} malformed JSONL record(s); discovery incomplete."
            inventory = ("\n[PASSIVE SUBDOMAIN INVENTORY — NOT ACTIVELY VERIFIED]\n"
                         + "\n".join(sorted(found)[:100])) if found else ""
            return ScannerOutput(note + inventory,
                                 status="PARTIAL" if valid_rows else "FAILED",
                                 evidence=bool(found))
        if not found:
            return ScannerOutput("[*] No in-scope subdomains discovered.", evidence=False)
        return ScannerOutput("[PASSIVE SUBDOMAIN INVENTORY — NOT ACTIVELY VERIFIED]\n" +
                             "\n".join(sorted(found)[:100]), evidence=True)
    except (ValueError, OSError) as exc:
        return ScannerOutput(f"[!] subfinder: {exc}", status="FAILED", evidence=False)


def run_katana(target: str, *, cancel_event=None) -> ScannerOutput:
    """Bounded same-host crawl, returning only validated in-scope URLs."""
    cancelled = _cancelled_before_start(cancel_event)
    if cancelled is not None:
        return cancelled
    try:
        import json
        from urllib.parse import urlsplit
        origin = web_endpoint(target, _web_target)
        allowed = urlsplit(origin)
        executable = find_native("katana")
        if not executable:
            raise ValueError("Katana not installed; set PENX_KATANA_PATH")
        outcome = _process_outcome(_run_external(katana_args(executable, origin), timeout=90,
                                               cancel_event=cancel_event))
        if outcome.status != "COMPLETE":
            return ScannerOutput(str(outcome)[:2000], status=outcome.status, evidence=False)
        found = set()
        failures = 0
        malformed = 0
        valid_rows = 0
        for line in str(outcome).splitlines():
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except ValueError:
                malformed += 1
                continue
            if not isinstance(item, dict):
                malformed += 1
                continue
            if item.get("error"):
                failures += 1
                continue  # A requested URL with an i/o timeout was NOT crawled.
            request = item.get("request")
            candidate = request.get("endpoint") if isinstance(request, dict) else None
            if (not isinstance(candidate, str) or not candidate
                    or any(ord(ch) < 32 or ch.isspace() for ch in candidate)):
                malformed += 1
                continue
            try:
                parsed = urlsplit(candidate)
                if not parsed.hostname or parsed.scheme not in ("http", "https"):
                    malformed += 1
                    continue
                same_origin = (
                    parsed.scheme == allowed.scheme
                    and parsed.hostname == allowed.hostname
                    and parsed.port == allowed.port
                    and not parsed.username and not parsed.password
                )
            except ValueError:
                # Keep valid crawl data but do not silently discard bad rows.
                malformed += 1
                continue
            valid_rows += 1
            if same_origin:
                found.add(parsed._replace(fragment="").geturl()[:350])
        if failures or malformed:
            notes = []
            if failures:
                notes.append(f"{failures} failed HTTP request(s), e.g. timeout")
            if malformed:
                notes.append(f"{malformed} malformed JSONL record(s)")
            note = "[!] Katana had " + " and ".join(notes) + "; crawl incomplete."
            urls = "\n".join(sorted(found)[:100])
            return ScannerOutput(
                note + ("\n[SAME-HOST CRAWL INVENTORY]\n" + urls if urls else ""),
                status="PARTIAL" if valid_rows or failures else "FAILED",
                evidence=bool(found),
            )
        if not found:
            return ScannerOutput("[*] No in-scope URLs discovered (no pages verified).", evidence=False)
        return ScannerOutput("[SAME-HOST CRAWL INVENTORY]\n" +
                             "\n".join(sorted(found)[:100]), evidence=True)
    except (ValueError, OSError) as exc:
        return ScannerOutput(f"[!] katana: {exc}", status="FAILED", evidence=False)


ENDPOINT_MAPPING_REQUEST_BUDGET = 80
ENDPOINT_MAPPING_CRAWL_PAGE_CAP = 24
ENDPOINT_MAPPING_RATE = 2  # Both native processes are sequential, not parallel.


def run_endpoint_mapping(target: str, *, cancel_event=None) -> ScannerOutput:
    """Explicitly selected Katana -> directory ffuf pass for one web origin.

    This is a conservative *planned* HTTP request budget. Katana's -mdp
    limits crawled pages, not every auxiliary browser/network exchange;
    native per-process rate caps + timeouts are additional protections.
    No query-parameter value fuzzing, mutations, authentication or redirects.
    """
    cancelled = _cancelled_before_start(cancel_event)
    if cancelled is not None:
        return cancelled
    try:
        origin = web_endpoint(target, _web_target)
        katana = find_native("katana")
        ffuf = find_native("ffuf")
        if not katana or not ffuf:
            return ScannerOutput(
                "[!] Endpoint mapping needs both Katana and ffuf installed; "
                "run --setup-native or configure PENX_KATANA_PATH and "
                "PENX_FFUF_PATH. No scan started.",
                status="FAILED", evidence=False,
            )
        words = ffuf_words()
        # No older persisted inventory is allowed to authorize a new active
        # request: only this completed crawler's parsed URLs select directories.
        current = EndpointInventory(origin)
        crawl = _process_outcome(_run_external(
            katana_args(katana, origin, mapping=True),
            timeout=18, cancel_event=cancel_event,
        ))
        if cancel_event is not None and cancel_event.is_set():
            return ScannerOutput("[!] Endpoint mapping cancelled during Katana.",
                                 status="PARTIAL", evidence=False)
        if crawl.status != "COMPLETE":
            return ScannerOutput("[!] Katana mapping did not complete; no ffuf probes "
                                 "were started.\n" + str(crawl)[:1200],
                                 status=crawl.status, evidence=False)
        discovered, malformed = current.collect_jsonl(str(crawl), "katana")
        if not discovered:
            return ScannerOutput(
                "[!] Katana did not return any validated same-origin endpoints; "
                "no follow-on ffuf requests were started."
                + (f" ({malformed} unusable JSONL rows)" if malformed else ""),
                status="PARTIAL" if malformed else "COMPLETE",
                evidence=False,
            )
        # One root pass plus up to two distinctly discovered directories.
        # Reserve page slots for the crawler before allocating ffuf words;
        # never silently exceed the request-plan ceiling across directories.
        parents = [origin] + current.paths_for_fuzz(max_dirs=2)
        slots = ENDPOINT_MAPPING_REQUEST_BUDGET - ENDPOINT_MAPPING_CRAWL_PAGE_CAP
        each = min(len(words), slots // len(parents))
        if each < 1:
            raise ValueError("Endpoint mapping budget exhausted before ffuf")
        selected = words[:each]
        notes: list[str] = []
        if malformed:
            notes.append(f"[!] Katana had {malformed} rejected or malformed rows.")
        notes.append(
            f"[MAPPING PLAN] Same origin: {origin}; at most "
            f"{ENDPOINT_MAPPING_CRAWL_PAGE_CAP} crawler pages + "
            f"{len(parents) * len(selected)} ffuf candidates; "
            f"native request rate <= {ENDPOINT_MAPPING_RATE}/s, sequential "
            "processes; page cap is not a wire-level total-request guarantee."
        )
        partial = bool(malformed)
        with tempfile.TemporaryDirectory(prefix="penx_endpoint_ffuf_") as folder:
            wordlist = Path(folder) / "safe-paths.txt"
            wordlist.write_text("\n".join(selected) + "\n", encoding="utf-8")
            for parent in parents:
                # A cancellable gap prevents a burst at process boundaries.
                if cancel_event is not None:
                    if cancel_event.wait(0.6):
                        partial = True
                        notes.append("[!] Mapping cancelled before next ffuf pass.")
                        break
                else:
                    time.sleep(0.6)
                result = _process_outcome(_run_external(
                    ffuf_args(ffuf, parent, wordlist, mapping=True),
                    timeout=20, cancel_event=cancel_event,
                ))
                if cancel_event is not None and cancel_event.is_set():
                    partial = True
                    notes.append("[!] Mapping cancelled during ffuf.")
                    break
                if result.status != "COMPLETE":
                    # Empty ffuf stdout can mean zero matching paths. Do not
                    # present it as verified negative coverage or a finding.
                    if str(result).strip() == "[!] Tool returned no output.":
                        notes.append(f"[*] No ffuf matches reported for {parent}.")
                        continue
                    partial = True
                    notes.append(f"[!] ffuf incomplete at {parent}: {str(result)[:220]}")
                    break
                count, rejected = current.collect_jsonl(str(result), "ffuf")
                notes.append(f"[*] ffuf at {parent}: {count} in-scope result(s)")
                if rejected:
                    partial = True
                    notes.append(f"[!] ffuf rejected {rejected} malformed/out-of-scope rows.")
        # Merge only verified same-origin metadata; not requests, secrets,
        # and especially not older URLs as new scan targets.
        try:
            saved = load_inventory(origin)
            for url, row in current.entries.items():
                for source in row["sources"]:
                    if saved.add(url, source):
                        saved.entries[url]["parameters"].update(row["parameters"])
            location = save_inventory(saved)
            notes.append(f"[*] Endpoint inventory stored: {location.name}")
        except (OSError, ValueError) as exc:
            partial = True
            notes.append(f"[!] Endpoint inventory could not be saved: {type(exc).__name__}")
        notes.append(current.summary())
        return ScannerOutput("\n".join(notes),
                             status="PARTIAL" if partial else "COMPLETE",
                             evidence=bool(current.entries))
    except (ValueError, OSError, UnicodeError) as exc:
        return ScannerOutput(f"[!] Endpoint mapping: {exc}",
                             status="FAILED", evidence=False)


def run_tls_check(target: str, *, cancel_event=None) -> ScannerOutput:
    """Check verified HTTPS handshake, certificate expiry and negotiated TLS."""
    cancelled = _cancelled_before_start(cancel_event)
    if cancelled is not None:
        return cancelled
    import socket
    import ssl
    from datetime import datetime, timezone
    from urllib.parse import urlsplit
    try:
        origin = web_endpoint(target, _web_target)
        parsed = urlsplit(origin)
        if parsed.scheme != "https":
            raise ValueError("TLS check requires an https:// target")
        host = parsed.hostname
        port = parsed.port or 443
        # Explicitly reject SSLv2/v3 and TLS 1.0/1.1. CodeQL's
        # py/insecure-protocol rule requires this before wrap_socket().
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        # One bounded retry for transient connect/TLS timeouts; continue to
        # require standard certificate verification and TLS >= 1.2.
        for attempt in range(2):
            cancelled = _cancelled_after_io(cancel_event)
            if cancelled is not None:
                return cancelled
            try:
                with socket.create_connection((host, port), timeout=6) as raw:
                    raw.settimeout(6)
                    with context.wrap_socket(raw, server_hostname=host) as tls:
                        cert = tls.getpeercert()
                        protocol = tls.version() or "unknown"
                        cipher = tls.cipher()
                break
            except (TimeoutError, socket.timeout):
                if attempt:
                    raise TimeoutError("TLS handshake timed out twice (6s per attempt)")
        cancelled = _cancelled_after_io(cancel_event)
        if cancelled is not None:
            return cancelled
        expiry = cert.get("notAfter", "") if isinstance(cert, dict) else ""
        if not isinstance(expiry, str):
            expiry = ""
        expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(expiry), timezone.utc) if expiry else None
        days_left = (expires - datetime.now(timezone.utc)).days if expires else None
        return ScannerOutput(
            f"[VERIFIED TLS HANDSHAKE] {host}:{port}\n"
            f"Protocol: {protocol}\n"
            f"Cipher: {cipher[0] if cipher else 'unknown'}\n"
            f"Certificate expires: {expires.isoformat() if expires else 'unknown'}\n"
            f"Days remaining: {days_left if days_left is not None else 'unknown'}\n"
            "Note: This is not a full cipher-suite audit.",
            evidence=True)
    except (OSError, ValueError, ssl.SSLError) as exc:
        cancelled = _cancelled_after_io(cancel_event)
        if cancelled is not None:
            return cancelled
        return ScannerOutput(f"[!] TLS verification failed: {exc}", status="FAILED", evidence=False)


TOOLS_MENU = {
    '1': ('nmap', run_nmap),
    '2': ('whois', run_whois),
    '3': ('web fingerprint', run_whatweb),
    '4': ('HTTP headers', run_curl_headers),
    '5': ('DNS', run_dig),
    '6': ('nikto (optional)', run_nikto),
    '7': ('nuclei (explicit opt-in)', run_nuclei),
    '8': ('httpx / ProjectDiscovery (native)', run_httpx),
    '9': ('ffuf (bounded wordlist, explicit opt-in)', run_ffuf),
    'e': ('endpoint inventory: Katana + targeted ffuf (explicit opt-in)', run_endpoint_mapping),
    's': ('subfinder (passive subdomains)', run_subfinder),
    'c': ('katana (same-host crawl, explicit opt-in)', run_katana),
    'd': ('TLS certificate and handshake', run_tls_check),
}


def run_default_recon(target: str) -> dict:
    print(f'\n[*] Starting recon on: {target}\n' + '─' * 50)
    results = {}
    for key, keyname in [('1', 'nmap'), ('2', 'whois'), ('3', 'whatweb'),
                         ('4', 'curl_headers'), ('5', 'dig')]:
        try:
            results[keyname] = TOOLS_MENU[key][1](target)
        except Exception as exc:
            message = f"[!] {keyname} failed ({type(exc).__name__}): {str(exc)[:200]}"
            print(message)
            results[keyname] = ScannerOutput(message, status="FAILED", evidence=False)
    print('─' * 50 + '\n[+] Recon complete.\n')
    return results


def run_single_tool(tool_key: str, target: str) -> str:
    if tool_key in TOOLS_MENU:
        return TOOLS_MENU[tool_key][1](target)
    return f'[!] Unknown tool key: {tool_key}'



ALLOWED_TOOLS = {'nmap', 'whois', 'whatweb', 'curl', 'dig', 'nikto'}


def run_tool_by_command(command_str: str, authorized_target: str | None = None) -> str:
    """Run only a whitelisted adapter against exactly the authorized session target.

    Tool instructions originate in untrusted LLM output. A missing session scope,
    a different target, multiple targets, or an ambiguous command is refused.
    Suggested command flags are intentionally ignored; only safe adapters run.
    """
    if not authorized_target:
        return '[!] Blocked model tool call: no authorized session target.'
    try:
        expected = _host(authorized_target).rstrip('.').casefold()
        parts = shlex.split(command_str, posix=True)
        if not parts:
            return '[!] Blocked model tool call: empty command.'
        tool = parts[0].replace('\\', '/').split('/')[-1].lower().removesuffix('.exe')
        if tool not in ALLOWED_TOOLS:
            return f'[!] Blocked model tool: {tool!r} is not permitted.'
        # Never silently ignore model-suggested flags: that made the model
        # believe a redirect-following curl call had actually been executed.
        # The fixed adapters do NOT implement arbitrary CLI options/paths.
        allowed_nmap = {'-sV', '-sC'}  # -Pn is NOT part of the fixed adapter.
        candidates = []
        for arg in parts[1:]:
            if arg.startswith('-'):
                if tool == 'nmap' and arg in allowed_nmap:
                    continue
                return (f'[!] Blocked model tool call: unsupported flag {arg!r}; '
                        f'no command was run. Supported form: [TOOL: {tool} {expected}]. '
                        'The built-in adapter applies fixed safe options; do not retry flags.')
            if tool == 'dig' and arg.upper() in {'A', 'AAAA', 'MX', 'NS', 'TXT'}:
                # The fixed DNS adapter reads all standard records for the single host.
                continue
            candidates.append(arg)
        if not candidates or len(candidates) != 1:
            return ('[!] Blocked model tool call: expected exactly one target; '
                    f'use [TOOL: {tool} {expected}] without paths or extra arguments.')
        # Explicit URL paths/ports/redirects cannot be honored by these fixed adapters.
        if tool in {'curl', 'whatweb'} and '://' in candidates[0]:
            parsed_url = urlsplit(candidates[0])
            if parsed_url.path not in ('', '/') or parsed_url.query or parsed_url.port not in (None, 80, 443):
                return ('[!] Blocked model tool call: custom paths, query strings or '
                        'ports are not supported by this adapter; no request was made.')
        parsed = _host(candidates[0]).rstrip('.').casefold()
        if parsed != expected:
            return ('[!] Blocked model tool call: target differs from authorized session target. '
                    'Subdomains and DNS TXT sublabels require a separate explicitly authorized '
                    'scan target; do not retry this request.')
        handlers = {'nmap': run_nmap, 'whois': run_whois, 'whatweb': run_whatweb,
                    'curl': run_curl_headers, 'dig': run_dig, 'nikto': run_nikto}
        # Use the user-specified session target, not the LLM-supplied URL/port.
        return handlers[tool](authorized_target)
    except (ValueError, TypeError) as exc:
        return f'[!] Blocked model tool call: {exc}'




from penx_app.domain.scan_models import ReconChoice


def interactive_tool_run(target: str) -> str | ReconChoice | None:
    from penx_app.cli.scanner_menu import interactive_tool_run as choose
    return choose(target, menu=TOOLS_MENU, formatter=format_recon_for_llm)

if __name__ == '__main__':
    target = input('Enter authorized test target (IP or domain): ').strip()
    print(format_recon_for_llm(run_default_recon(target)))
