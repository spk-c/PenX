"""PX-305: offline linting of user-supplied configuration / IaC files.

Read-only, bounded and deterministic. The linter never executes configuration,
never opens a network connection and never interprets credentials; it only
matches explicit, unambiguous weak settings inside a local file. Rule IDs and
evidence line references are stable so reports are reproducible.
"""
from __future__ import annotations

import hashlib
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path

from penx_app.domain.local_review import strict_json

MAX_CONFIG_BYTES = 1_048_576  # 1 MiB, same bound as other offline local files.

# Deliberately conservative: only the most sensitive host paths are flagged so
# normal application mounts (e.g. /app, /srv/data) are not reported.
SENSITIVE_HOST_PATHS = {
    '/', '/etc', '/root', '/boot', '/dev', '/proc', '/sys',
}

# Weak cipher tokens (exact match on the positive, non-excluded portion).
WEAK_CIPHER_TOKENS = {
    'RC4', 'ARC4', 'DES', '3DES', 'MD5', 'EXPORT', 'ANONYMOUS',
    'RC2', 'RC6', 'LOW', 'NULL',
}

_WEAK_PROTOCOLS = {'TLSv1', 'TLSv1.1'}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    line: int
    message: str
    evidence: str

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "line": self.line,
            "message": self.message,
            "evidence": self.evidence,
        }


@dataclass(frozen=True)
class LocalConfigReport:
    format: str
    source: str
    source_sha256: str
    line_count: int
    byte_size: int
    coverage: str
    findings: tuple[Finding, ...]
    limitations: tuple[str, ...]

    def to_dict(self) -> dict:
        return {
            "schema": "penx-config-lint-v1",
            "format": self.format,
            "source": self.source,
            "source_sha256": self.source_sha256,
            "line_count": self.line_count,
            "byte_size": self.byte_size,
            "coverage": self.coverage,
            "findings": [f.to_dict() for f in self.findings],
            "limitations": list(self.limitations),
            "network_access": False,
        }


def read_local_config(file_path: str | Path,
                      max_bytes: int = MAX_CONFIG_BYTES) -> tuple[str, str, int]:
    """Refuse symlink swaps, non-regular files and unbounded inputs.

    Returns ``(text, sha256_hex, byte_size)``. All failures raise ``ValueError``
    so callers can fail closed.
    """
    path = Path(file_path)
    try:
        initial = path.lstat()
    except OSError as exc:
        raise ValueError('Config input is not an accessible ordinary file') from exc
    if not stat.S_ISREG(initial.st_mode) or initial.st_size > max_bytes:
        raise ValueError('Config input must be an ordinary file at most 1 MiB')
    # O_NOFOLLOW + post-open identity checks reject link/replacement races.
    # O_NONBLOCK prevents a regular-file-to-FIFO race from blocking open().
    flags = (os.O_RDONLY | getattr(os, 'O_BINARY', 0)
             | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    fd = os.open(path, flags)
    try:
        opened, named = os.fstat(fd), path.lstat()
        identity = (opened.st_dev, opened.st_ino)
        if (not stat.S_ISREG(opened.st_mode) or not stat.S_ISREG(named.st_mode)
                or identity != (named.st_dev, named.st_ino)
                or identity != (initial.st_dev, initial.st_ino)
                or opened.st_size > max_bytes):
            raise ValueError('Config input must be an unchanged ordinary file at most 1 MiB')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(max_bytes + 1)
    finally:
        os.close(fd)
    if len(raw) > max_bytes:
        raise ValueError('Config input exceeds 1 MiB')
    try:
        text = raw.decode('utf-8-sig')
    except UnicodeDecodeError as exc:
        raise ValueError('Config input must be valid UTF-8 text') from exc
    return text, hashlib.sha256(raw).hexdigest(), len(raw)


def detect_format(text: str, path: str) -> str:
    """Classify the file as nginx, apache, docker_compose, k8s, tls_policy or unknown."""
    if (re.search(r'(?ms)^\s*events\s*\{', text)
            or re.search(r'(?ms)^\s*http\s*\{', text)
            or re.search(r'(?ms)^\s*server\s*\{', text)):
        return 'nginx'
    if (re.search(r'(?mis)^\s*<directory\b', text)
            or re.search(r'(?mis)^\s*<virtualhost\b', text)
            or re.search(r'(?mis)^\s*<location\b', text)
            or re.search(r'(?mis)^\s*servertokens\b', text)):
        return 'apache'
    if re.search(r'(?ms)^\s*services:\s*$', text):
        return 'docker_compose'
    if (re.search(r'(?ms)^\s*apiVersion\s*:', text)
            and re.search(r'(?ms)^\s*kind\s*:', text)):
        return 'k8s'
    if _looks_like_tls_policy(text):
        return 'tls_policy'
    return 'unknown'


def _looks_like_tls_policy(text: str) -> bool:
    if not text.lstrip().startswith('{'):
        return False
    lower = text.lower()
    return ('"protocols"' in lower or '"ciphers"' in lower
            or '"ssl_protocols"' in lower or '"ssl_ciphers"' in lower)


def _nginx_rules(text: str) -> list[Finding]:
    findings: list[Finding] = []
    for i, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        m = re.match(r'^ssl_protocols\s+(.+?);', stripped, re.IGNORECASE)
        if m:
            protocols = set(m.group(1).split())
            if protocols & _WEAK_PROTOCOLS:
                findings.append(Finding(
                    'NGINX_SSLV1', 'high', i,
                    'Weak TLS protocol enabled (TLSv1/TLSv1.1)', stripped[:120]))
        m = re.match(r'^ssl_ciphers\s+(.+?);', stripped, re.IGNORECASE)
        if m:
            for token in m.group(1).split(':'):
                token = token.strip()
                if not token or token.startswith('!'):
                    continue
                if token.upper() in WEAK_CIPHER_TOKENS:
                    findings.append(Finding(
                        'NGINX_SSL_CIPHERS', 'medium', i,
                        'Weak cipher enabled in ssl_ciphers', stripped[:120]))
                    break
        if re.match(r'^allow\s+all\s*;', stripped, re.IGNORECASE):
            findings.append(Finding(
                'NGINX_ALLOW_ALL', 'medium', i,
                'Access allowed for all clients', stripped[:120]))
        m = re.match(r'^server_tokens\s+(on|off)\s*;', stripped, re.IGNORECASE)
        if m and m.group(1).lower() == 'on':
            findings.append(Finding(
                'NGINX_SERVER_TOKENS_ON', 'low', i,
                'Server tokens enabled (server_tokens on)', stripped[:120]))
    return findings


def _apache_rules(text: str) -> list[Finding]:
    findings: list[Finding] = []
    for i, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        m = re.match(r'^options\s+(.+)', stripped, re.IGNORECASE)
        if m:
            options = m.group(1).replace(';', ' ').split()
            if (any(o in ('Indexes', '+Indexes') for o in options)
                    and '-Indexes' not in options):
                findings.append(Finding(
                    'APACHE_INDEXES', 'medium', i,
                    'Directory listing (Indexes) enabled', stripped[:120]))
        m = re.match(r'^servertokens\s+(\S+)', stripped, re.IGNORECASE)
        if m and m.group(1).lower() == 'public':
            findings.append(Finding(
                'APACHE_SERVER_TOKENS', 'low', i,
                'ServerTokens Public discloses version', stripped[:120]))
        m = re.match(r'^traceenabled\s+(on|off)', stripped, re.IGNORECASE)
        if m and m.group(1).lower() == 'on':
            findings.append(Finding(
                'APACHE_TRACE_ON', 'low', i,
                'TRACE method enabled (TraceEnabled On)', stripped[:120]))
    return findings


def _is_secret_name(name: str) -> bool:
    up = name.upper()
    return any(token in up for token in (
        'SECRET', 'PASSWORD', 'TOKEN', 'CREDENTIAL',
        'PRIVATE_KEY', 'API_KEY', 'AUTH'))


def _is_secret_value(value: str) -> bool:
    value = value.strip().strip('"\'')
    if not value:
        return False
    if value.startswith('${'):
        return False
    if value.lower() in ('true', 'false', 'null', 'none'):
        return False
    try:
        float(value)
        return False
    except ValueError:
        pass
    return True


def _check_env_secret(item: str, line: int, findings: list[Finding]) -> None:
    m = re.match(r'^([A-Za-z0-9_]+)\s*[:=]\s*(.*)$', item)
    if not m:
        return
    name, value = m.group(1), m.group(2)
    if _is_secret_name(name) and _is_secret_value(value):
        # Redact the value so reports never expose a real credential; the
        # variable name and line number are enough to locate the finding.
        findings.append(Finding(
            'YAML_ENV_SECRET', 'medium', line,
            'Possible secret value in environment variable',
            f'{name}=***'[:120]))


def _check_scalar(key: str, value: str, line: int, findings: list[Finding]) -> None:
    value = value.strip().strip('"\'')
    if key == 'privileged' and value.lower() == 'true':
        findings.append(Finding(
            'YAML_PRIVILEGED', 'critical', line,
            'Container running as privileged', str(value)[:120]))
    elif key == 'user' and value in ('root', '0', '0:0'):
        findings.append(Finding(
            'YAML_ROOT_USER', 'high', line,
            'Container running as root', str(value)[:120]))


def _yaml_rules(text: str) -> list[Finding]:
    """Bounded, line-based parser for docker-compose and k8s YAML.

    No YAML library is used, so aliases and recursive anchors are never
    expanded (no billion-laughs). Unknown keys are ignored.
    """
    findings: list[Finding] = []
    block: str | None = None
    block_indent = -1
    for i, line in enumerate(text.splitlines(), 1):
        if not line.strip() or line.strip().startswith('#'):
            continue
        indent = len(line) - len(line.lstrip())
        stripped = line.strip()
        if stripped.startswith('-'):
            item = stripped[1:].strip()
            if block == 'volumes':
                parts = item.split(':')
                if len(parts) >= 2:
                    host = parts[0].strip().strip('"\'')
                    if host in SENSITIVE_HOST_PATHS:
                        findings.append(Finding(
                            'YAML_HOST_MOUNT', 'high', i,
                            'Sensitive host path mounted into container',
                            stripped[:120]))
            elif block == 'ports':
                if item.strip().strip('"\'').startswith('0.0.0.0:'):
                    findings.append(Finding(
                        'YAML_ALL_INTERFACE_PORT', 'medium', i,
                        'Port bound to all interfaces (0.0.0.0)', stripped[:120]))
            elif block == 'environment':
                _check_env_secret(item, i, findings)
            continue
        m = re.match(r'^([A-Za-z0-9_]+)\s*:\s*(.*)$', stripped)
        if not m:
            continue
        key, value = m.group(1).lower(), m.group(2).strip()
        if block == 'environment' and key not in ('volumes', 'ports', 'environment'):
            _check_env_secret(f'{key}={value}', i, findings)
        if key in ('volumes', 'ports', 'environment'):
            block, block_indent = key, indent
        else:
            block = None
            block_indent = -1
        _check_scalar(key, value, i, findings)
    return findings


def _collect_protocols(doc: dict) -> list[str]:
    protocols: list[str] = []
    if isinstance(doc.get('protocols'), list):
        protocols.extend(p for p in doc['protocols'] if isinstance(p, str))
    tls = doc.get('tls')
    if isinstance(tls, dict):
        value = tls.get('ssl_protocols')
        if isinstance(value, str):
            protocols.extend(value.split())
        elif isinstance(value, list):
            protocols.extend(p for p in value if isinstance(p, str))
    return protocols


def _collect_ciphers(doc: dict) -> list[str]:
    ciphers: list[str] = []
    raw = doc.get('ciphers')
    if isinstance(raw, list):
        ciphers.extend(c for c in raw if isinstance(c, str))
    elif isinstance(raw, str):
        ciphers.append(raw)
    tls = doc.get('tls')
    if isinstance(tls, dict):
        value = tls.get('ssl_ciphers')
        if isinstance(value, str):
            ciphers.extend(value.split(':'))
        elif isinstance(value, list):
            ciphers.extend(c for c in value if isinstance(c, str))
    return ciphers


def _tls_policy_rules(text: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        doc = strict_json(text)
    except (ValueError, UnicodeError, RecursionError):
        return findings
    if not isinstance(doc, dict):
        return findings
    protocols = _collect_protocols(doc)
    for protocol in protocols:
        if protocol in _WEAK_PROTOCOLS:
            findings.append(Finding(
                'TLS_PROTOCOL', 'high', 1,
                'Weak TLS protocol in policy',
                'protocols: ' + str(protocols)[:110]))
            break
    ciphers = _collect_ciphers(doc)
    for cipher in ciphers:
        if cipher.upper() in WEAK_CIPHER_TOKENS:
            findings.append(Finding(
                'TLS_CIPHER', 'medium', 1,
                'Weak cipher in policy',
                'ciphers: ' + str(ciphers)[:110]))
            break
    return findings


def lint_local_config(path: str | Path) -> LocalConfigReport:
    """Lint one local configuration file and return a bounded report."""
    text, sha256, size = read_local_config(path)
    lines = text.splitlines()
    fmt = detect_format(text, str(path))
    if fmt == 'nginx':
        findings = _nginx_rules(text)
    elif fmt == 'apache':
        findings = _apache_rules(text)
    elif fmt in ('docker_compose', 'k8s'):
        findings = _yaml_rules(text)
    elif fmt == 'tls_policy':
        findings = _tls_policy_rules(text)
    else:
        findings = []
    # Deduplicate identical (rule, line) pairs; keep report order stable.
    seen: set[tuple[str, int]] = set()
    unique: list[Finding] = []
    for finding in findings:
        key = (finding.rule_id, finding.line)
        if key not in seen:
            seen.add(key)
            unique.append(finding)
    if fmt == 'unknown':
        coverage = 'PARTIAL'
    else:
        coverage = 'COMPLETE'
    limitations = [
        'Rules are heuristic and source-based; findings are observations, not exploitability proofs.',
    ]
    if fmt == 'unknown':
        limitations.append(
            'Format not recognized; no rules applied. Supported: nginx, apache, '
            'docker-compose, k8s, TLS policy.')
    return LocalConfigReport(
        format=fmt,
        source=str(path),
        source_sha256=sha256,
        line_count=len(lines),
        byte_size=size,
        coverage=coverage,
        findings=tuple(unique),
        limitations=tuple(limitations),
    )
