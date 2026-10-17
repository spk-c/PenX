"""Explicit configuration loading; importing this module does not load user state."""
from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path
from types import MappingProxyType
from typing import Mapping
from urllib.parse import urlsplit


@dataclass(frozen=True)
class Settings:
    """Immutable configuration snapshot. Secrets are excluded from its repr."""
    values: Mapping[str, object] = field(repr=False)

    def __getattr__(self, name: str):
        try:
            return self.values[name]
        except KeyError:
            raise AttributeError(name) from None


def environment_values(env: Mapping[str, str], env_file: Path | None) -> dict[str, str]:
    """dotenv semantics: process values win, including during interpolation."""
    from dotenv import dotenv_values
    from dotenv.variables import parse_variables

    values: dict[str, str] = {}
    if env_file is not None and env_file.is_file():
        for key, value in dotenv_values(env_file, interpolate=False).items():
            if value is not None:
                scope = {**values, **env}
                values[key] = ''.join(atom.resolve(scope) for atom in parse_variables(value))
    return {**values, **env}


def load_settings(*, root: Path, env: Mapping[str, str] | None = None,
                  env_file: Path | None = None) -> Settings:
    """Read a snapshot without modifying os.environ or creating directories."""
    from penx_app.analysis.llm_client import normalize_base_url

    source = environment_values(os.environ if env is None else env, env_file)
    def get(name: str, default: str) -> str:
        return source.get('PENX_' + name, source.get('METATRON_' + name, default))
    def number(name: str, default: str, *, minimum: int = 0) -> int:
        try:
            value = int(get(name, default))
        except ValueError:
            raise ValueError(f'PENX_{name} must be an integer.') from None
        if value < minimum:
            raise ValueError(f'PENX_{name} must be at least {minimum}.')
        return value
    def enabled(name: str, default: str = 'on') -> bool:
        return get(name, default).strip().lower() not in ('off', 'false', '0', 'no')

    base = normalize_base_url(get('LLM_URL', 'http://localhost:1234'))
    if urlsplit(base).scheme not in ('http', 'https'):
        raise ValueError('PENX_LLM_URL must use HTTP or HTTPS.')
    mode = get('STRUCTURED_OUTPUT', 'auto').strip().lower()
    if mode not in ('auto', 'strict', 'off'):
        raise ValueError('PENX_STRUCTURED_OUTPUT must be auto, strict, or off.')
    engine = get('DB_ENGINE', 'sqlite').strip().lower()
    if engine not in ('sqlite', 'mariadb'):
        raise ValueError('Invalid PENX_DB_ENGINE. Expected sqlite or mariadb.')
    new_db, old_db = root / 'data' / 'penx.db', root / 'data' / 'metatron.db'
    default_db = old_db if old_db.is_file() and not new_db.exists() else new_db
    values = dict(
        LLM_BASE_URL=base, LLM_URL=base.rstrip('/') + '/v1/chat/completions',
        LLM_MODELS_URL=base.rstrip('/') + '/v1/models',
        MODEL_NAME=get('MODEL', 'your-local-model'), LLM_API_KEY=get('LLM_API_KEY', ''),
        STRUCTURED_MODE=mode, VERIFY_SOURCES=enabled('VERIFY_SOURCES'),
        # Model-originated queries leave the local machine; never enable by default.
        ALLOW_MODEL_WEB_SEARCH=enabled('ALLOW_MODEL_WEB_SEARCH', 'off'),
        NVD_API_KEY=get('NVD_API_KEY', ''), CVE_DISCOVERY=enabled('CVE_DISCOVERY'),
        CVE_MAX_SERVICES=number('CVE_MAX_SERVICES', '3'),
        CVE_MAX_PACKAGES=number('CVE_MAX_PACKAGES', '4'),
        CVE_MAX_RESULTS=number('CVE_MAX_RESULTS', '15'),
        GITHUB_ADVISORY_TOKEN=get('GITHUB_ADVISORY_TOKEN', ''),
        CVE_PRIORITY=enabled('CVE_PRIORITY'),
        CVE_DISTRO_HINT=get('CVE_DISTRO_HINT', '').strip().lower(),
        CVE_MAX_VERIFY=max(1, min(number('CVE_MAX_VERIFY', '20', minimum=-2147483648), 30)),
        PACKAGE_INVENTORY=get('PACKAGE_INVENTORY', '').strip(),
        DEBIAN_TRACKER_JSON=get('DEBIAN_TRACKER_JSON', '').strip(),
        SCAN_INPUT_MAX_CHARS=max(2048, min(number('SCAN_INPUT_MAX_CHARS', '60000', minimum=-2147483648), 500000)),
        MAX_TOKENS=number('MAX_TOKENS', '8192', minimum=1),
        TOP_K=number('TOP_K', '10'), LLM_TIMEOUT=number('TIMEOUT', '600', minimum=1),
        MAX_TOOL_LOOPS=number('MAX_LOOPS', '9'),
        DB_HOST=get('DB_HOST', 'localhost'), DB_USER=get('DB_USER', 'penx'),
        DB_PASSWORD=get('DB_PASS', ''), DB_NAME=get('DB_NAME', 'penx'),
        DB_ENGINE=engine, DB_PATH=get('DB_PATH', str(default_db)),
        NMAP_PATH=get('NMAP_PATH', ''),
        NIKTO_PATH=get('NIKTO_PATH', str(root / 'vendor' / 'nikto' / 'program' / 'nikto.pl')),
        WHATWEB_PATH=get('WHATWEB_PATH', str(root / 'vendor' / 'whatweb' / 'whatweb')),
    )
    return Settings(MappingProxyType(values))
