#!/usr/bin/env python3
"""
PenX - search.py
Free web search via DuckDuckGo — no API key needed.
Also fetches and extracts plain text from URLs.
Used by LLM tool dispatch when AI writes [SEARCH: query]
"""

from collections.abc import Callable
from itertools import islice
import ipaddress
import socket
from urllib.parse import urlsplit
import requests
from requests.adapters import HTTPAdapter
from urllib3.connection import HTTPSConnection
from urllib3.connectionpool import HTTPSConnectionPool
from urllib3.exceptions import NewConnectionError
from bs4 import BeautifulSoup
try:
    from ddgs import DDGS
except ImportError:
    DDGS = None


# ─────────────────────────────────────────────
# DDG SEARCH
# ─────────────────────────────────────────────

MAX_SEARCH_RESULTS = 10
MAX_SEARCH_QUERY_CHARS = 2048


def _search_field(value: object, limit: int) -> str:
    """Keep remote snippets single-line and bounded for model-facing results."""
    if not isinstance(value, str):
        return ""
    return " ".join(value.split())[:limit]


def web_search(query: str, max_results: int = 5, *,
               ddgs_factory: Callable | None = None,
               emit: Callable | None = None) -> str:
    """Bound untrusted search responses before they reach the model context.

    Invalid third-party entries are skipped rather than discarding valid hits.
    Never materialize an unbounded provider iterator into a list.
    """
    if (not isinstance(query, str) or not query.strip()
            or len(query) > MAX_SEARCH_QUERY_CHARS):
        return "[!] Invalid or oversized search query."
    if type(max_results) is not int or not 1 <= max_results <= MAX_SEARCH_RESULTS:
        return "[!] Invalid search result limit."
    (print if emit is None else emit)(f"  [*] Searching: {query}")
    if DDGS is None and ddgs_factory is None:
        return "[!] Missing ddgs package. Install requirements.txt."
    try:
        with (DDGS if ddgs_factory is None else ddgs_factory)() as ddgs:
            # The client should honour max_results, but do not rely on it to
            # enforce our local capture and output size budget.
            results = []
            for row in islice(ddgs.text(query, max_results=max_results), max_results):
                if not isinstance(row, dict):
                    continue
                title = _search_field(row.get("title"), 240)
                url = _search_field(row.get("href"), 512)
                body = _search_field(row.get("body"), 1200)
                if not title or not url:
                    continue
                results.append((title, url, body))

        if not results:
            return "[!] No usable search results found."

        output = f"[WEB SEARCH RESULTS FOR: {query}]\n"
        output += "─" * 50 + "\n"
        for i, (title, url, body) in enumerate(results, 1):
            output += f"\n[{i}] {title}\n"
            output += f"    URL     : {url}\n"
            output += f"    Snippet : {body}\n"
        return output

    except Exception as exc:
        # Provider diagnostics can contain user query data or tokens. Avoid
        # copying raw exception text into a model-facing result.
        return f"[!] Search failed ({type(exc).__name__})."

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


class _PublicOnlyHTTPSConnection(HTTPSConnection):
    """Connect to an explicitly verified public socket address only.

    Filtering DNS in fetch_page(), followed by requests.get(), is vulnerable
    to a second DNS lookup selecting a private/rebound address. Perform the
    DNS lookup and public-address check inside the actual socket connection
    instead. urllib3 still performs TLS/SNI/hostname validation for the
    original (unmodified) HTTPS URL after _new_conn returns the socket.
    """

    def _new_conn(self):
        try:
            answers = socket.getaddrinfo(
                self._dns_host, self.port, type=socket.SOCK_STREAM
            )
        except OSError as exc:
            raise NewConnectionError(self, "Public HTTPS hostname resolution failed") from exc
        last_error = None
        for family, kind, protocol, _canonical, address in answers:
            try:
                resolved_ip = ipaddress.ip_address(address[0])
                if not resolved_ip.is_global or resolved_ip.is_multicast:
                    continue
            except (ValueError, TypeError, IndexError):
                continue
            connection = None
            try:
                # Use the already resolved sockaddr: never run a second DNS
                # lookup through urllib3.util.connection.create_connection().
                connection = socket.socket(family, kind, protocol)
                for option in self.socket_options or ():
                    connection.setsockopt(*option)
                connection.settimeout(self.timeout)
                if self.source_address is not None:
                    connection.bind(self.source_address)
                connection.connect(address)
                return connection
            except OSError as exc:
                last_error = exc
                if connection is not None:
                    connection.close()
        raise NewConnectionError(
            self, "No reachable public HTTPS address was resolved"
        ) from last_error


class _PublicOnlyHTTPSPool(HTTPSConnectionPool):
    ConnectionCls = _PublicOnlyHTTPSConnection


class _PublicOnlyHTTPSAdapter(HTTPAdapter):
    """Keep standard HTTPS/TLS verification with a public-IP-only connection."""

    def init_poolmanager(self, connections, maxsize, block=False, **kwargs):
        super().init_poolmanager(connections, maxsize, block=block, **kwargs)
        # PoolManager's default map is shared; copy before changing this
        # instance to avoid affecting unrelated requests and clients.
        self.poolmanager.pool_classes_by_scheme = (
            self.poolmanager.pool_classes_by_scheme.copy()
        )
        self.poolmanager.pool_classes_by_scheme["https"] = _PublicOnlyHTTPSPool


def _allowed_page_url(url: str) -> bool:
    """Only public HTTPS endpoints; redirects are never followed."""
    try:
        parsed = urlsplit(url)
        host = parsed.hostname
        if (parsed.scheme != "https" or not host or parsed.username is not None
                or parsed.password is not None or parsed.fragment
                or parsed.port == 0 or len(url) > 2048
                or any(ch.isspace() or ord(ch) < 32 for ch in url)):
            return False
        name = host.casefold().rstrip(".")
        if (name in ("localhost", "localhost.localdomain")
                or name.endswith((".local", ".localhost", ".internal", ".test"))):
            return False
        # IP literals (including IPv6 and historic IPv4 notation) must be
        # evaluated before the public-domain dot requirement. A valid IPv6
        # address has no dot; encoded IPv4 can have no dot either.
        try:
            literal_ip = ipaddress.ip_address(name)
            return literal_ip.is_global and not literal_ip.is_multicast
        except ValueError:
            # Operating systems also accept historic numeric IPv4 forms
            # such as 127.1, 2130706433 or 0x7f000001. ipaddress rejects
            # those spellings, but the HTTP client's resolver may still
            # connect to 127.0.0.1. Check the same legacy parser without
            # resolving DNS or sending a request.
            try:
                numeric_ip = ipaddress.IPv4Address(socket.inet_aton(name))
                return numeric_ip.is_global and not numeric_ip.is_multicast
            except OSError:
                # A non-IP DNS name must have a dotted public suffix.
                return "." in name
    except (ValueError, TypeError):
        return False


def fetch_page(url: str, max_chars: int = 3000, *,
               http_get: Callable | None = None) -> str:
    """Fetch a bounded external HTTPS page, without following redirects.

    Production network connections use a dedicated HTTPS transport that
    refuses non-public DNS answers *at socket creation*. The original host
    remains the TLS certificate/Server Name Indication identity. Injected
    transports are meant for offline tests and have independent trust policy.
    """
    if not isinstance(url, str) or not _allowed_page_url(url):
        return "[!] Page fetch blocked: requires a public HTTPS URL."
    resp = None
    try:
        headers = {"User-Agent": "PenX/0.4"}
        if http_get is None:
            # Do not use ambient HTTP(S)_PROXY variables here: an arbitrary
            # proxy would resolve the host outside our checked transport.
            with requests.Session() as session:
                session.trust_env = False
                session.mount("https://", _PublicOnlyHTTPSAdapter())
                resp = session.get(url, headers=headers, timeout=15,
                                   allow_redirects=False, stream=True)
                return _read_public_page(resp, max_chars)
        # An injected transport is reserved for offline tests/callers that
        # explicitly supply their own network safety policy.
        resp = http_get(url, headers=headers, timeout=15,
                        allow_redirects=False, stream=True)
        return _read_public_page(resp, max_chars)
    except requests.exceptions.ConnectionError:
        return "[!] Could not connect to a public HTTPS address."
    except requests.exceptions.Timeout:
        return "[!] Page fetch timed out."
    except requests.exceptions.HTTPError:
        return "[!] HTTP error fetching public page."
    except Exception as exc:
        return f"[!] Fetch failed ({type(exc).__name__})."
    finally:
        if resp is not None:
            resp.close()


def _read_public_page(resp, max_chars: int) -> str:
    """Decode a verified transport's bounded response without retaining HTML."""
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
