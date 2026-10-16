"""Windows installation health check. Never scans a network."""
import os
import sys
import importlib.util
import requests
from pathlib import Path
from penx_app.config import DB_ENGINE, DB_PATH, LLM_MODELS_URL, MODEL_NAME, LLM_API_KEY
from penx_app.analysis.llm_client import fetch_models, resolve_model_name, explain_http_error
from penx_app.scanners.tools import tool_status
from penx_app.scanners.scanner_runtime import find_runtime, executable_env, find_nmap, npcap_present
from penx_app.config import WHATWEB_PATH, NIKTO_PATH, NMAP_PATH
import subprocess


def scanner_self_check(label, runtime, script, args):
    """Non-scanning startup check for upstream programs."""
    interpreter = find_runtime(runtime)
    if not interpreter or not script or not Path(script).is_file():
        print(f'[WARN] {label}: executable or script not found')
        return False
    try:
        command = [interpreter, script, *args] if label == 'WhatWeb' else [interpreter, '-c', script]
        result = subprocess.run(command,
                                cwd=str(Path(script).parent),
                                env=executable_env(interpreter),
                                capture_output=True, text=True,
                                encoding='utf-8', errors='replace', timeout=45)
        ok = result.returncode == 0
        details = (result.stdout + result.stderr).strip().splitlines()
        print(f"[{'OK' if ok else 'WARN'}] {label}: " + (details[-1][:180] if details else 'No output'))
        return ok
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f'[WARN] {label} failed self-check: {exc}')
        return False


def main():
    passed = True
    print(f'Python: {sys.version.split()[0]}  |  OS: {os.name}')
    print(f'Database: {DB_ENGINE}' + (f' -> {DB_PATH}' if DB_ENGINE == 'sqlite' else ''))
    try:
        from penx_app.storage.db import get_connection
        conn = get_connection()
        c = conn.cursor()
        c.execute('SELECT 1')
        assert c.fetchone()[0] == 1
        conn.close()
        print('[OK] Database + schema are ready')
    except Exception as exc:
        print(f'[FAIL] Database: {exc}')
        passed = False
    for pkg in ('requests', 'bs4', 'dotenv', 'dns', 'whois', 'ddgs', 'reportlab'):
        found = importlib.util.find_spec(pkg) is not None
        print(f"[{'OK' if found else 'MISSING'}] Python {pkg}")
        passed &= found
    nmap = find_nmap(NMAP_PATH)
    if nmap:
        print(f'[OK] Nmap executable: {nmap}')
    else:
        print('[WARN] Nmap is missing')
        passed = False
    if os.name == 'nt':
        driver = npcap_present()
        print('[OK] Npcap driver detected' if driver else '[WARN] Npcap driver not found')
        passed &= driver
    for name, status in tool_status().items():
        print(f'[*] {name}: {status}')
    passed &= scanner_self_check('WhatWeb', 'ruby', WHATWEB_PATH, ['--version'])
    passed &= scanner_self_check('Nikto', 'perl', NIKTO_PATH, [])
    print(f'[*] Local model: {MODEL_NAME}')
    print(f'[*] API URL: {LLM_MODELS_URL}')
    try:
        models = fetch_models(LLM_MODELS_URL, api_key=LLM_API_KEY, timeout=3)
        print('[OK] LLM server available: ' + (', '.join(models[:6]) or '(no model listed)'))
        model_id = resolve_model_name(MODEL_NAME, LLM_MODELS_URL, api_key=LLM_API_KEY)
        if model_id not in models:
            print(f'[WARN] Configured model {model_id!r} was not listed by the server')
        else:
            print(f'[OK] Selected model: {model_id}')
    except requests.exceptions.HTTPError as exc:
        if getattr(exc.response, "status_code", None) in (401, 403):
            print('[FAIL] Local LLM: ' + explain_http_error(exc))
            passed = False
        else:
            print(f'[WARN] LLM server not yet available: HTTP {getattr(exc.response, "status_code", "unknown")}')
    except Exception as exc:
        print(f'[WARN] LLM server not yet available: {type(exc).__name__}')
    print('Only scan systems you own or have explicit permission to test.')
    print('[OK] Required components detected' if passed else '[WARN] Some scanner components are missing or failed self-check')
    return 0 if passed else 1


if __name__ == '__main__':
    sys.exit(main())
