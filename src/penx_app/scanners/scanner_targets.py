"""Pure scanner target normalization and URL construction.

This module does not launch processes, resolve DNS or make network requests.
Callers retain their legacy tools._host/_web_target/_urls entrypoints.
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

MAX_CIDR_ADDRESSES = 256


def normalize_host(target: str, *, max_addresses: int = MAX_CIDR_ADDRESSES) -> str:
    """Normalize an IP/domain/URL without allowing flags as a hostname."""
    value = target.strip()
    if not value or any(c.isspace() for c in value) or value.startswith('-'):
        raise ValueError('Enter a valid IP address or domain (no whitespace/options).')
    if '://' in value:
        parsed = urlsplit(value)
        if parsed.scheme not in ('http', 'https') or not parsed.hostname:
            raise ValueError('Only http:// or https:// URLs are accepted.')
        # Never reinterpret credentials or a malformed port as a scan target.
        if parsed.username is not None or parsed.password is not None or parsed.fragment:
            raise ValueError('Userinfo and URL fragments are unsupported.')
        try:
            url_port = parsed.port
        except ValueError as exc:
            raise ValueError('Invalid URL port.') from exc
        if url_port == 0 or parsed.netloc.endswith(':'):
            raise ValueError('Invalid URL port.')
        value = parsed.hostname
    else:
        # Distinguish network syntax from a domain URL path. Invalid IP/CIDR
        # must fail instead of silently scanning the host outside the intended
        # prefix scope.
        if '/' in value:
            try:
                network = ipaddress.ip_network(value, strict=False)
            except ValueError as exc:
                hostpart = value.split('/', 1)[0]
                if ':' in hostpart or re.fullmatch(r'[0-9.]+', hostpart):
                    raise ValueError('Invalid IP/CIDR subnet.') from exc
                value = hostpart
            else:
                if network.num_addresses > max_addresses:
                    raise ValueError(
                        f'CIDR target too large ({network.num_addresses} addresses); '
                        f'maximum is {max_addresses}. Split into smaller authorized subnets.'
                    )
                return str(network)
        # Handle host:port, preserving bracketed IPv6.
        if value.startswith('[') or value.count(':') == 1:
            # Validate the *whole* authority. Previously the suffix of
            # '[::1]junk' and the invalid port in 'host:garbage' were silently
            # discarded, potentially scanning a different target.
            try:
                parsed = urlsplit('//' + value)
                port = parsed.port
                host = parsed.hostname
            except ValueError as exc:
                raise ValueError('Invalid host or port.') from exc
            if (not host or parsed.netloc != value or parsed.path or parsed.query
                    or parsed.fragment or parsed.username is not None
                    or parsed.password is not None
                    or parsed.netloc.endswith(':') or port == 0):
                raise ValueError('Invalid host or port.')
            if value.startswith('['):
                if not value.casefold().startswith('[' + host.casefold() + ']'):
                    raise ValueError('Invalid bracketed IPv6 address.')
                try:
                    ipaddress.IPv6Address(host)
                except ValueError as exc:
                    raise ValueError('Invalid bracketed IPv6 address.') from exc
            elif port is None:
                raise ValueError('Invalid host port.')
            value = host
    if '/' in value:
        raise ValueError('Invalid CIDR or URL path.')
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    value = value.rstrip('.')
    # Purely numeric terminal labels on a non-IP value are never a valid
    # resolvable domain TLD; don't allow malformed IPv4 as a "domain".
    if value.split('.')[-1].isdigit():
        raise ValueError('Invalid numeric hostname or IP address.')
    try:
        # IDNA converts Unicode domain names without allowing CLI option injection.
        value = '.'.join(label.encode('idna').decode('ascii') for label in value.split('.'))
    except UnicodeError as exc:
        raise ValueError('Invalid internationalized domain name.') from exc
    if (len(value) > 253 or not value or '..' in value or
            any(not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label)
                for label in value.split('.'))):
        raise ValueError('Invalid domain. Use an IP or a hostname.')
    return value.lower()


def normalize_web_target(target: str, *, host_resolver=normalize_host) -> str:
    """Preserve an explicit URL/port for web scanners, rejecting CLI options/CIDR."""
    value = target.strip()
    # A scheme-less path or query is ambiguous and previously got discarded,
    # changing the requested scan endpoint silently. Require an explicit URL.
    if '://' not in value and any(char in value for char in '/?#'):
        raise ValueError('Include http:// or https:// when supplying a URL path or query.')
    host = host_resolver(value)
    if '/' in host:
        raise ValueError('Web scanners expect one host/URL, not a CIDR subnet.')
    if '://' not in value:
        # Bare IPv6 has no unambiguous port; brackets are required for one.
        if ':' in host and not value.startswith('['):
            return f'[{host}]'
        parsed = urlsplit('//' + value)
    else:
        parsed = urlsplit(value)
    if parsed.username or parsed.password or parsed.fragment:
        raise ValueError('Userinfo and URL fragments are unsupported.')
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError('Invalid URL port.') from exc
    if port == 0 or parsed.netloc.endswith(':'):
        raise ValueError('Invalid URL port.')
    if '://' not in value:
        authority = f'[{host}]' if ':' in host else host
        return authority + (f':{port}' if port is not None else '')
    return value


def target_urls(target: str, *, web_target=normalize_web_target) -> list[str]:
    value = web_target(target)
    if '://' in value:
        return [value]
    return [f'https://{value}', f'http://{value}']
