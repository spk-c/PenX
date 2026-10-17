"""Stable scanner identities and consent policy, independent of menu labels."""
from dataclasses import dataclass


@dataclass(frozen=True)
class ScannerSpec:
    key: str
    id: str
    consent: bool = False
    resource_sensitive: bool = False


SCANNERS = {spec.key: spec for spec in (
    ScannerSpec('1', 'nmap'), ScannerSpec('2', 'whois'),
    ScannerSpec('3', 'whatweb'), ScannerSpec('4', 'http_headers'),
    ScannerSpec('5', 'dns'), ScannerSpec('6', 'nikto', resource_sensitive=True),
    ScannerSpec('7', 'nuclei', True, True),
    ScannerSpec('8', 'httpx', resource_sensitive=True),
    ScannerSpec('9', 'ffuf', True, True),
    ScannerSpec('e', 'endpoint_mapping', True, True), ScannerSpec('s', 'subfinder'),
    ScannerSpec('c', 'katana', True, True), ScannerSpec('d', 'tls'),
)}
CONSENT_KEYS = frozenset(key for key, spec in SCANNERS.items() if spec.consent)
