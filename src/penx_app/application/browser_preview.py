"""PX-301 first slice: deliberately limited Playwright-based loopback browser preview.

This is NOT a vulnerability detector or a general website scanner. It renders
an explicitly authorized local lab app, collects bounded navigation and form
*structure*, and refuses cross-origin, unsafe-method, websocket and service-
worker traffic. No requests may be initiated by LLM output.
"""
from __future__ import annotations

import hashlib
import ipaddress
import posixpath
import time
from collections import deque
from dataclasses import dataclass
from urllib.parse import unquote, urljoin, urlsplit, urlunsplit

MAX_PAGES = 5
MAX_LINKS = 60
MAX_FORMS = 20
INIT_SCRIPT = r"""
(() => {
  class BlockedSocket {
    constructor() { throw new Error('PenX browser preview: socket disabled'); }
  }
  Object.defineProperty(window, 'WebSocket', { value: BlockedSocket });
  Object.defineProperty(window, 'EventSource', { value: BlockedSocket });
  Object.defineProperty(window, 'RTCPeerConnection', { value: BlockedSocket });
  try { Object.defineProperty(navigator, 'sendBeacon', { value: () => false }); } catch (_) {}
})();
"""


def _path(value: str) -> str:
    path = unquote(value or "/")
    if (not path.startswith("/") or len(path) > 512
            or any(ord(c) < 32 or ord(c) == 127 for c in path)
            or any(part in {".", ".."} for part in path.split("/"))):
        raise ValueError("Unsupported or ambiguous browser path")
    canonical = posixpath.normpath(path)
    return canonical if canonical.startswith("/") else "/"


def _loopback_host(hostname: str | None) -> str:
    if hostname == "localhost":
        return "127.0.0.1"
    if hostname not in {"127.0.0.1", "::1"}:
        raise ValueError("Browser preview only permits literal loopback endpoints")
    if not ipaddress.ip_address(hostname).is_loopback:
        raise ValueError("Browser target is not loopback")
    return hostname


@dataclass(frozen=True)
class BrowserScope:
    start_url: str
    scheme: str
    host: str
    port: int
    root_path: str

    @classmethod
    def parse(cls, url: str) -> "BrowserScope":
        if not isinstance(url, str) or len(url) > 2048:
            raise ValueError("Invalid browser target")
        parsed = urlsplit(url)
        if (parsed.scheme not in {"http", "https"} or not parsed.netloc
                or parsed.username is not None or parsed.password is not None
                or parsed.query or parsed.fragment):
            raise ValueError("Browser target must be a URL without credentials or query")
        host = _loopback_host(parsed.hostname)
        port = parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80)
        if not 1 <= port <= 65535:
            raise ValueError("Invalid browser port")
        path = _path(parsed.path)
        navigate_path = path + "/" if parsed.path.endswith("/") and path != "/" else path
        authority = f"[{host}]" if ":" in host else host
        authority += f":{port}"
        return cls(urlunsplit((parsed.scheme, authority, navigate_path, "", "")),
                   parsed.scheme, host, port, path)

    def allows(self, url: str) -> bool:
        """Origin + path-prefix gate, evaluated again for EVERY request."""
        try:
            parsed = urlsplit(url)
            return (parsed.scheme == self.scheme
                    and _loopback_host(parsed.hostname) == self.host
                    and (parsed.port if parsed.port is not None else
                         (443 if parsed.scheme == "https" else 80)) == self.port
                    and parsed.username is None and parsed.password is None
                    and self.in_path(_path(parsed.path)))
        except (ValueError, TypeError):
            return False

    def in_path(self, path: str) -> bool:
        return (self.root_path == "/" or path == self.root_path
                or path.startswith(self.root_path.rstrip("/") + "/"))

    def candidate(self, current: str, href: str) -> str | None:
        """Never follow fragments, external links, query URLs or non-HTTP hrefs."""
        if not isinstance(href, str) or not href or len(href) > 2048:
            return None
        try:
            url = urljoin(current, href)
            parsed = urlsplit(url)
            if parsed.query or not self.allows(url):
                return None
            path = _path(parsed.path)
            navigate_path = path + "/" if parsed.path.endswith("/") and path != "/" else path
            return urlunsplit((parsed.scheme, parsed.netloc, navigate_path, "", ""))
        except (ValueError, TypeError):
            return None


def _route_request(route, scope: BrowserScope, stats: dict) -> None:
    """Deny unsafe methods and every request beyond the exact local scope."""
    request = route.request
    if request.method not in {"GET", "HEAD"} or not scope.allows(request.url):
        stats["blocked_requests"] += 1
        route.abort()
        return
    route.continue_()


def _page_structure(page, scope: BrowserScope, url: str) -> tuple[dict, list[str]]:
    # No DOM snapshots, input values, cookies, response bodies or query tokens.
    links = page.eval_on_selector_all(
        "a[href]", "(nodes, n) => nodes.slice(0, n).map(x => x.getAttribute('href'))",
        MAX_LINKS + 1)
    forms = page.eval_on_selector_all(
        "form", "(nodes, n) => nodes.slice(0, n).map(x => ({"
        "method: x.getAttribute('method'), action: x.getAttribute('action')}))",
        MAX_FORMS + 1)
    if not isinstance(links, list) or not isinstance(forms, list):
        raise ValueError("Browser returned invalid DOM structure")
    links_truncated = len(links) > MAX_LINKS
    forms_truncated = len(forms) > MAX_FORMS
    candidates = []
    for href in links[:MAX_LINKS]:
        candidate = scope.candidate(url, href)
        if candidate is not None and candidate not in candidates:
            candidates.append(candidate)
    form_rows = []
    for form in forms[:MAX_FORMS]:
        if not isinstance(form, dict):
            continue
        method = str(form.get("method") or "GET").upper()
        action = scope.candidate(url, form.get("action") or url)
        if method in {"GET", "POST"} and action is not None:
            form_rows.append({"method": method, "action_path": _path(urlsplit(action).path)})
    observed_path = _path(urlsplit(url).path)
    return ({"path": observed_path, "link_paths": [_path(urlsplit(x).path) for x in candidates],
             "forms": form_rows, "finding_count": 0,
             "links_truncated": links_truncated,
             "forms_truncated": forms_truncated}, candidates)


def crawl_loopback(
    target: str, *, authorized: bool, consent: bool,
    max_pages: int = 3, timeout: int = 8, budget: int = 60,
    channel: str = "chromium", playwright_factory=None,
    clock=time.monotonic,
) -> dict:
    """Render bounded same-origin GET pages inside an isolated browser context.

    Explicit consent is mandatory. A successful result means DOM collection,
    NOT a clean website or proof of a vulnerability. Any blocked outbound
    traffic or page failure makes coverage incomplete.
    """
    scope = BrowserScope.parse(target)
    if authorized is not True or consent is not True:
        raise ValueError("Browser preview requires explicit authorization and consent")
    if (type(max_pages) is not int or not 1 <= max_pages <= MAX_PAGES
            or type(timeout) is not int or not 2 <= timeout <= 20
            or type(budget) is not int or not 10 <= budget <= 120
            or channel not in {"chromium", "chrome"}):
        raise ValueError("Invalid bounded browser preview configuration")
    if playwright_factory is None:
        try:
            from playwright.sync_api import sync_playwright
        except ImportError as exc:
            raise ValueError("Optional Playwright browser dependency is unavailable") from exc
        playwright_factory = sync_playwright
    deadline = clock() + budget
    pending = deque([scope.start_url])
    seen: set[str] = set()
    collected: list[dict] = []
    stats = {"blocked_requests": 0, "failed_pages": 0}
    with playwright_factory() as playwright:
        browser = playwright.chromium.launch(
            headless=True, channel=None if channel == "chromium" else "chrome",
            args=["--disable-background-networking"])
        try:
            context = browser.new_context(
                service_workers="block", accept_downloads=False,
                ignore_https_errors=False)
            try:
                context.add_init_script(script=INIT_SCRIPT)
                context.route("**/*", lambda route: _route_request(route, scope, stats))
                page = context.new_page()
                page.on("popup", lambda popup: popup.close())
                while pending and len(collected) < max_pages:
                    remaining = deadline - clock()
                    if remaining < 2:
                        stats["failed_pages"] += len(pending)
                        break
                    requested = pending.popleft()
                    if requested in seen:
                        continue
                    seen.add(requested)
                    try:
                        response = page.goto(
                            requested, wait_until="domcontentloaded",
                            timeout=int(min(timeout, remaining) * 1000))
                        if not scope.allows(page.url):
                            raise ValueError("Browser navigated beyond approved scope")
                        if response is None or response.status >= 400:
                            raise ValueError("Browser response was unsuccessful")
                        entry, candidates = _page_structure(page, scope, page.url)
                        collected.append(entry)
                        for candidate in candidates:
                            if candidate not in seen and candidate not in pending:
                                pending.append(candidate)
                    except Exception:
                        # Browser libraries vary in exception type. Do not echo
                        # untrusted page content, paths, URLs or credentials.
                        stats["failed_pages"] += 1
            finally:
                context.close()
        finally:
            browser.close()

    incomplete = bool(stats["blocked_requests"] or stats["failed_pages"] or pending
                      or any(item["links_truncated"] or item["forms_truncated"]
                             for item in collected))
    return {
        "schema": "penx-browser-preview-v1",
        "status": "PARTIAL" if incomplete else "COMPLETE",
        "state": "collected-not-assessed",
        "target_origin_sha256": hashlib.sha256(
            f"{scope.scheme}://{scope.host}:{scope.port}".encode()).hexdigest(),
        "scope_path": scope.root_path,
        "visited_pages": len(collected),
        "max_pages": max_pages,
        "blocked_requests": stats["blocked_requests"],
        "failed_pages": stats["failed_pages"],
        "queued_pages_unvisited": len(pending),
        "pages": collected,
        "vulnerability_verified": False,
        "vulnerability_scanning_performed": False,
        "limitations": (
            "Synthetic browser DOM structure only, not a security verdict; "
            "no form submission, authenticated session, external host access, "
            "CVE verification, exploitation or model execution. Unknown is not safe."
        ),
    }
