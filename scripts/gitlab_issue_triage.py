"""Opt-in GitLab issue triage adapter for PenX.

Reuses the established, source-grounded reviewer without giving issue text
access to shell commands. Runs for one issue per scheduled pipeline. Requires
a masked PENX_GITLAB_TRIAGE_TOKEN with GitLab API scope. Never closes issues.
"""
from __future__ import annotations

from contextlib import contextmanager
import json
import os
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlsplit
from urllib.request import Request, urlopen

try:
    from . import issue_triage as review_engine
except ImportError:
    import issue_triage as review_engine

PROJECT_PATH = "SLP-DEV1/PenX"
PROJECT_ID = "87731916"
API = "https://gitlab.com/api/v4/projects/" + PROJECT_ID
MARKER = review_engine.MARKER


def api_json(path: str, token: str, *, method: str = "GET", payload: dict | None = None):
    if not path.startswith("/") or path.startswith("//") or ".." in path.split("/"):
        raise ValueError("Unsafe GitLab API path")
    url = API + path
    req = Request(url, method=method, data=(
        json.dumps(payload).encode("utf-8") if payload is not None else None
    ), headers={
        "PRIVATE-TOKEN": token, "Content-Type": "application/json",
        "Accept": "application/json", "User-Agent": "PenX-GitLab-Triage/1.0"
    })
    with urlopen(req, timeout=30) as response:
        raw = response.read(1_000_001)
    if len(raw) > 1_000_000:
        raise ValueError("Oversized GitLab API response")
    return json.loads(raw) if raw else {}


def _as_github_issue(issue: dict) -> dict:
    """Adapt GitLab fields into the existing reviewed issue contract."""
    labels = issue.get("labels") or []
    return {
        **issue,
        "number": int(issue["iid"]),
        "body": str(issue.get("description") or ""),
        "title": str(issue.get("title") or ""),
        "labels": [{"name": s} for s in labels if isinstance(s, str)],
        "user": {"login": str((issue.get("author") or {}).get("username") or "")},
    }


@contextmanager
def gitlab_review_transport(token: str):
    original = review_engine.request_json

    def adapted(url: str, _token: str, *, method: str = "GET",
                payload: dict | None = None, timeout: int = 35):
        if url == review_engine.MODEL_URL:
            return original(url, _token, method=method, payload=payload, timeout=timeout)
        prefix = review_engine.API_ROOT + "/repos/" + PROJECT_PATH + "/issues"
        if not url.startswith(prefix) or method != "GET":
            raise ValueError("Disallowed issue-review API request")
        suffix = url[len(prefix):]
        if suffix.startswith("/"):
            num = suffix[1:].split("?", 1)[0]
            if not num.isdecimal() or int(num) <= 0:
                raise ValueError("Invalid GitLab issue IID")
            return _as_github_issue(api_json(f"/issues/{int(num)}", token))
        if suffix and not suffix.startswith("?"):
            raise ValueError("Unsupported issue lookup")
        params = parse_qs(suffix[1:] if suffix else "")
        if any(k not in {"state", "per_page", "page"} for k in params):
            raise ValueError("Unsupported issue list filter")
        state = params.get("state", ["all"])[0]
        if state not in ("all", "open", "closed"):
            raise ValueError("Invalid issue state")
        page = int(params.get("page", ["1"])[0])
        if not 1 <= page <= 10:
            raise ValueError("Issue page outside bounded range")
        gitlab_state = {"open": "opened", "closed": "closed", "all": "all"}[state]
        batch = api_json(f"/issues?state={gitlab_state}&per_page=100&page={page}", token)
        if not isinstance(batch, list):
            raise ValueError("Invalid GitLab issue list response")
        return [_as_github_issue(x) for x in batch if isinstance(x, dict)]

    review_engine.request_json = adapted
    try:
        yield
    finally:
        review_engine.request_json = original


def choose_issue(token: str) -> int | None:
    """Oldest open issue not yet carrying a PenX triage comment."""
    for page in range(1, 4):
        items = api_json(f"/issues?state=opened&order_by=created_at&sort=asc&per_page=100&page={page}", token)
        if not isinstance(items, list):
            raise ValueError("Invalid issue listing")
        for item in items:
            if not isinstance(item, dict) or not isinstance(item.get("iid"), int):
                continue
            iid = item["iid"]
            notes = api_json(f"/issues/{iid}/notes?per_page=100", token)
            if not isinstance(notes, list):
                raise ValueError("Invalid notes response")
            if not any(MARKER in str(note.get("body") or "") for note in notes if isinstance(note, dict)):
                return iid
        if len(items) < 100:
            break
    return None


def publish_issue(token: str, iid: int, report: dict):
    if report.get("repo") != PROJECT_PATH or report.get("issue_number") != iid:
        raise ValueError("Mismatched triage report")
    verdict = report.get("verdict")
    if verdict not in review_engine.LABELS:
        raise ValueError("Unexpected verdict")
    body = report.get("comment")
    if not isinstance(body, str) or not body.startswith(MARKER) or len(body) > 4000:
        raise ValueError("Invalid reviewer comment")
    body = body.replace(
        "https://github.com/" + PROJECT_PATH + "/blob/",
        "https://gitlab.com/" + PROJECT_PATH + "/-/blob/"
    ).replace(
        "https://github.com/" + PROJECT_PATH + "/issues/",
        "https://gitlab.com/" + PROJECT_PATH + "/-/issues/"
    )
    # Check again before writing, to avoid duplicate scheduled comments.
    notes = api_json(f"/issues/{iid}/notes?per_page=100", token)
    if any(MARKER in str(n.get("body") or "") for n in notes if isinstance(n, dict)):
        return False
    label, color, description = review_engine.LABELS[verdict]
    existing = api_json(f"/issues/{iid}", token)
    current = set(existing.get("labels") or [])
    try:
        api_json("/labels", token, method="POST", payload={
            "name": label, "color": "#" + color, "description": description
        })
    except HTTPError as exc:
        if exc.code not in (400, 409):
            raise
    removed = ",".join(n for n in current if n.startswith("triage:") and n != label)
    api_json(f"/issues/{iid}", token, method="PUT", payload={
        "add_labels": label, "remove_labels": removed
    })
    api_json(f"/issues/{iid}/notes", token, method="POST", payload={"body": body})
    return True


def main() -> int:
    if os.environ.get("CI_PROJECT_PATH", PROJECT_PATH) != PROJECT_PATH:
        raise SystemExit("Refusing to run against another GitLab project")
    token = os.environ.get("PENX_GITLAB_TRIAGE_TOKEN", "")
    if not token:
        raise SystemExit("Masked PENX_GITLAB_TRIAGE_TOKEN CI variable is required")
    raw_iid = os.environ.get("PENX_GITLAB_TRIAGE_ISSUE_IID", "")
    if raw_iid and not raw_iid.isdecimal():
        raise SystemExit("Invalid PENX_GITLAB_TRIAGE_ISSUE_IID")
    iid = int(raw_iid) if raw_iid else choose_issue(token)
    if iid is None:
        print("No unreviewed GitLab issues.")
        return 0
    if not 0 < iid < 2**31:
        raise SystemExit("Invalid GitLab issue IID")
    # Read-only review, optional Groq provider, then one constrained API publish.
    with gitlab_review_transport(token):
        report = review_engine.review(PROJECT_PATH, iid, token, Path(__file__).resolve().parents[1])
    published = publish_issue(token, iid, report)
    print("Triage " + ("published" if published else "already exists") + f" for issue {iid}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
