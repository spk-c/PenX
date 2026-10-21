"""Offline PHP2Shell log and php.ini triage; never executes PoCs or contacts hosts."""
from __future__ import annotations
import re

MAX_LOCAL_BYTES = 2_000_000
_OOM = re.compile(r"\bAllowed memory size of \d+ bytes exhausted\b", re.I)
_PREINIT = re.compile(r"\bin Unknown on line 0\b", re.I)
_CRASH = re.compile(r"\b(?:segmentation fault|sigsegv|exit(?:ed)?(?:\s+on)?\s+signal\s+11)\b", re.I)
_FIELD = re.compile(r"\bPHP_SESSION_UPLOAD_PROGRESS\b", re.I)
_POST = re.compile(r'"POST\s+[^"\r\n]{1,300}"\s+5(?:00|02|03)\b', re.I)
_INI = re.compile(r"^\s*([a-z][a-z0-9_.-]{1,90})\s*=\s*(.*?)\s*$", re.I)
_POOL_INI = re.compile(
    r"^\s*php_(?:admin_)?(?:flag|value)\[\s*([a-z][a-z0-9_.-]{1,90})\s*\]\s*=\s*(.*?)\s*$",
    re.I,
)
_KEYS = ("session.upload_progress.enabled", "session.use_strict_mode", "fatal_error_backtraces")


def _lines(source: str) -> list[str]:
    if not isinstance(source, str) or len(source.encode("utf-8", errors="replace")) > MAX_LOCAL_BYTES:
        raise ValueError("Local evidence must be decoded text no larger than 2 MB")
    return source.splitlines()


def _bool_value(value: str) -> str:
    value = value.strip().strip("'\"").lower()
    if value in ("0", "off", "false", "no"):
        return "disabled"
    if value in ("1", "on", "true", "yes"):
        return "enabled"
    return "unrecognized"


def _config(text: str | None) -> dict:
    if text is None:
        return {"provided": False, "settings": {key: "not_checked" for key in _KEYS}}
    values: dict[str, set[str]] = {key: set() for key in _KEYS}
    for line in _lines(text):
        line = line.strip()
        if not line or line.startswith((";", "#", "[")):
            continue
        # php.ini uses name=value; PHP-FPM pool files may also express the
        # same settings through php_flag/php_admin_flag (or *_value).
        # These are file observations only: pool inheritance, per-dir
        # overrides and the running worker's effective values are unknown.
        match = _INI.fullmatch(line) or _POOL_INI.fullmatch(line)
        if match and match.group(1).lower() in values:
            values[match.group(1).lower()].add(
                _bool_value(match.group(2).split(";", 1)[0])
            )
    return {"provided": True, "settings": {
        key: ("not_observed" if not vals else
              next(iter(vals)) if len(vals) == 1 else "conflicting")
        for key, vals in values.items()
    }}


def _access(text: str | None) -> dict:
    if text is None:
        return {"provided": False, "upload_progress_field_mentions": 0,
                "http_post_500_502_503": 0}
    lines = _lines(text)
    return {
        "provided": True,
        "upload_progress_field_mentions": sum(bool(_FIELD.search(s)) for s in lines),
        "http_post_500_502_503": sum(bool(_POST.search(s)) for s in lines),
    }


def _error(text: str | None) -> dict:
    if text is None:
        return {"provided": False, "preinit_memory_errors": 0,
                "worker_crash_messages": 0}
    lines = _lines(text)
    return {
        "provided": True,
        "preinit_memory_errors": sum(bool(_OOM.search(s) and _PREINIT.search(s)) for s in lines),
        "worker_crash_messages": sum(bool(_CRASH.search(s)) for s in lines),
    }


def analyze_php2shell_local_artifacts(
    *, php_ini: str | None = None, access_log: str | None = None,
    error_log: str | None = None,
) -> dict:
    """Heuristic counts, not evidence of exploitability or correlated attacks."""
    config, access, errors = _config(php_ini), _access(access_log), _error(error_log)
    indicators = (access["upload_progress_field_mentions"]
                  + errors["preinit_memory_errors"] + errors["worker_crash_messages"])
    provided = access["provided"] or errors["provided"]
    triage = ("review_indicators" if indicators else
              "no_indicators_in_supplied_logs" if provided else "not_checked")
    return {
        "schema": "penx-php2shell-local-triage-v1",
        "triage": triage,
        "exploit_tested": False,
        "exploit_confirmed": False,
        "configuration": config,
        "access_log": access,
        "error_log": errors,
        "limitations": (
            "Counts are non-specific and not timestamp-correlated. An HTTP 500, "
            "PHP memory error, worker crash or upload-progress field may be "
            "unrelated to exploitation. Default access logs often omit form "
            "fields. Absence of indicators does not prove no attack. A supplied "
            "php.ini is not proof of the actual server or worker configuration. "
            "Disabling upload progress only mitigates some confirmed paths; "
            "apply vendor PHP patches for CVE-2026-109618 and CVE-2026-109619."
        ),
    }
