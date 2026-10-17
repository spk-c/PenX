#!/usr/bin/env python3
"""
PenX - search.py
Free web search via DuckDuckGo — no API key needed.
Also fetches and extracts plain text from URLs.
Used by LLM tool dispatch when AI writes [SEARCH: query]
"""

from collections.abc import Callable
import ipaddress
import socket
from urllib.parse import urlsplit
import requests
from bs4 import BeautifulSoup
try:
    from ddgs import DDGS
except ImportError:
    DDGS = None


# ─────────────────────────────────────────────
# DDG SEARCH
# ─────────────────────────────────────────────

def web_search(query: str, max_results: int = 5, *,
               ddgs_factory: Callable | None = None,
               emit: Callable | None = None) -> str:
    """
    Search DuckDuckGo and return formatted results.
    No API key. No rate limit issues for reasonable usage.
    Returns a string ready to paste into LLM prompt.
    """
    (print if emit is None else emit)(f"  [*] Searching: {query}")
    if DDGS is None and ddgs_factory is None:
        return "[!] Missing ddgs package. Install requirements.txt."
    try:
        with (DDGS if ddgs_factory is None else ddgs_factory)() as ddgs:
            results = list(ddgs.text(query, max_results=max_results))

        if not results:
            return "[!] No search results found."

        output = f"[WEB SEARCH RESULTS FOR: {query}]\n"
        output += "─" * 50 + "\n"
        for i, r in enumerate(results, 1):
            output += f"\n[{i}] {r['title']}\n"
            output += f"    URL     : {r['href']}\n"
            output += f"    Snippet : {r['body']}\n"

        return output

    except Exception as e:
        return f"[!] Search failed: {e}"


# ─────────────────────────────────────────────
# CVE SPECIFIC SEARCH
# ─────────────────────────────────────────────

def search_cve(cve_id: str, *, web_search_client: Callable | None = None,
               page_fetch_client: Callable | None = None,
               emit: Callable | None = None) -> str:
    """
    Search for a specific CVE.
    Queries DDG then also hits cve.mitre.org directly.
    """
    (print if emit is None else emit)(f"  [*] Looking up {cve_id}...")

    # DDG search first
    # Keep the terminal default, but let application callers route progress to
    # their own UI rather than printing from a research service.
    if web_search_client is None:
        def search(q: str, **kwargs) -> str:
            return web_search(q, emit=emit, **kwargs)
    else:
        search = web_search_client
    fetch = fetch_page if page_fetch_client is None else page_fetch_client
    ddg_results = search(f"{cve_id} vulnerability exploit details", max_results=3)

    # Direct MITRE fetch
    mitre_url = f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}"
    mitre_data = fetch(mitre_url, max_chars=2000)

    return f"{ddg_results}\n\n[MITRE CVE LOOKUP: {cve_id}]\n{mitre_data}"


def search_exploit(service: str, version: str, *,
                   web_search_client: Callable | None = None) -> str:
    """
    Search for known exploits for a service + version combo.
    e.g. search_exploit("apache", "2.4.49")
    """
    query = f"{service} {version} exploit CVE vulnerability 2023 2024"
    search = web_search if web_search_client is None else web_search_client
    return search(query, max_results=5)


def search_fix(vuln_name: str, *, web_search_client: Callable | None = None) -> str:
    """
    Search for mitigation/fix for a vulnerability.
    """
    query = f"how to fix {vuln_name} security mitigation patch"
    search = web_search if web_search_client is None else web_search_client
    return search(query, max_results=3)


# ─────────────────────────────────────────────
# PAGE FETCHER
# ─────────────────────────────────────────────

MAX_PAGE_BYTES = 512 * 1024


def _allowed_page_url(url: str) -> bool:
    """Only public HTTPS endpoints; redirects are never followed."""
    try:
        parsed = urlsplit(url)
        host = parsed.hostname
        if (parsed.scheme != "https" or not host or parsed.username is not None
                or parsed.password is not None or parsed.fragment
                or parsed.port == 0):
            return False
        name = host.casefold().rstrip(".")
        if (name in ("localhost", "localhost.localdomain")
                or name.endswith((".local", ".localhost", ".internal", ".test"))):
            return False
        # IP literals (including IPv6 and historic IPv4 notation) must be
        # evaluated before the public-domain dot requirement. A valid IPv6
        # address has no dot; encoded IPv4 can have no dot either.
        try:
            return ipaddress.ip_address(name).is_global
        except ValueError:
            # Operating systems also accept historic numeric IPv4 forms
            # such as 127.1, 2130706433 or 0x7f000001. ipaddress rejects
            # those spellings, but the HTTP client's resolver may still
            # connect to 127.0.0.1. Check the same legacy parser without
            # resolving DNS or sending a request.
            try:
                return ipaddress.IPv4Address(socket.inet_aton(name)).is_global
            except OSError:
                # A non-IP DNS name must have a dotted public suffix.
                return "." in name
    except (ValueError, TypeError):
        return False


def fetch_page(url: str, max_chars: int = 3000, *,
               http_get: Callable | None = None) -> str:
    """Fetch a bounded external HTTPS page, without following redirects.

    A private/internal target must not be fetched through model-supplied
    commands; arbitrary caller-selected public DNS domains still depend on
    DNS trust and must not be treated as a full anti-rebinding sandbox.
    """
    if not isinstance(url, str) or not _allowed_page_url(url):
        return "[!] Page fetch blocked: requires a public HTTPS URL."
    resp = None
    try:
        headers = {"User-Agent": "PenX/0.4"}
        client = requests.get if http_get is None else http_get
        resp = client(url, headers=headers, timeout=15,
                      allow_redirects=False, stream=True)
        if 300 <= resp.status_code < 400:
            return "[!] Page fetch refused a redirect."
        resp.raise_for_status()

        chunks = []
        total = 0
        for piece in resp.iter_content(chunk_size=8192):
            if not piece:
                continue
            total += len(piece)
            if total > MAX_PAGE_BYTES:
                return "[!] Page fetch response exceeded 512 KiB."
            chunks.append(piece)
        encoding = resp.encoding or "utf-8"
        soup = BeautifulSoup(b"".join(chunks).decode(encoding, errors="replace"),
                             "html.parser")
        for tag in soup(["script", "style", "nav", "footer", "header", "aside"]):
            tag.decompose()
        clean = "\n".join(l for l in soup.get_text(separator="\n", strip=True).splitlines()
                          if l.strip())
        limit = max(0, min(int(max_chars), 20000))
        if len(clean) > limit:
            clean = clean[:limit] + f"\n... [truncated at {limit} chars]"
        return clean
    except requests.exceptions.ConnectionError:
        return "[!] Could not connect to URL — check network."
    except requests.exceptions.Timeout:
        return "[!] Page fetch timed out."
    except requests.exceptions.HTTPError as e:
        return f"[!] HTTP error: {e}"
    except Exception as e:
        return f"[!] Fetch failed: {e}"
    finally:
        if resp is not None:
            resp.close()


# ─────────────────────────────────────────────
# TOOL DISPATCH HANDLER
# ─────────────────────────────────────────────

def handle_search_dispatch(query: str, *, general_search: Callable | None = None,
                           page_fetch: Callable | None = None,
                           emit: Callable | None = None) -> str:
    """
    Called by llm.py when AI writes [SEARCH: something].
    Smartly routes to CVE lookup, exploit search, or general search.
    """
    query = query.strip()
    if general_search is None:
        def search(q: str, **kwargs) -> str:
            return web_search(q, emit=emit, **kwargs)
    else:
        search = general_search
    fetch = fetch_page if page_fetch is None else page_fetch

    # CVE pattern — CVE-YYYY-NNNNN
    import re
    cve_pattern = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
    cve_match = cve_pattern.search(query)
    if cve_match:
        return search_cve(cve_match.group(), web_search_client=search,
                          page_fetch_client=fetch, emit=emit)

    # exploit keywords
    if any(word in query.lower() for word in ["exploit", "poc", "payload", "rce", "lfi", "sqli"]):
        return search(query + " exploit poc github", max_results=5)

    # fix/patch keywords
    if any(word in query.lower() for word in ["fix", "patch", "mitigate", "harden", "secure"]):
        return search_fix(query, web_search_client=search)

    # default general search
    return search(query, max_results=5)


# ─────────────────────────────────────────────
# QUICK TEST
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("[ search.py test ]\n")
    print("[1] General search")
    print("[2] CVE lookup")
    print("[3] Fetch a URL")
    choice = input("Choice: ").strip()

    if choice == "1":
        q = input("Query: ").strip()
        print(web_search(q))

    elif choice == "2":
        cve = input("CVE ID (e.g. CVE-2021-44228): ").strip()
        print(search_cve(cve))

    elif choice == "3":
        url = input("URL: ").strip()
        print(fetch_page(url))
