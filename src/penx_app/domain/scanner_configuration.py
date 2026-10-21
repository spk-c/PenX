"""Strict scanner options, with no command strings, paths, targets or secrets."""
from __future__ import annotations

from dataclasses import asdict, dataclass

from penx_app.scanners.registry import SCANNERS


@dataclass(frozen=True)
class ScannerConfiguration:
    scanner_key: str
    timeout_seconds: int | None = None
    ports: tuple[int, ...] = ()
    severities: tuple[str, ...] = ()
    rate_limit: int | None = None

    def __post_init__(self):
        if not isinstance(self.scanner_key, str) or self.scanner_key not in SCANNERS:
            raise ValueError('Unknown configured scanner')
        if self.timeout_seconds is not None and (
                type(self.timeout_seconds) is not int or not 30 <= self.timeout_seconds <= 900):
            raise ValueError('Scanner timeout must be an integer in 30..900')
        if (not isinstance(self.ports, tuple) or len(self.ports) > 100
                or any(type(port) is not int or not 1 <= port <= 65535 for port in self.ports)
                or len(set(self.ports)) != len(self.ports)):
            raise ValueError('Ports must be unique integers in 1..65535, at most 100')
        if self.ports and self.scanner_key != '1':
            raise ValueError('Explicit ports are supported only by Nmap')
        if (not isinstance(self.severities, tuple)
                or any(value not in ('low', 'medium', 'high', 'critical') for value in self.severities)
                or len(set(self.severities)) != len(self.severities)):
            raise ValueError('Invalid Nuclei severity subset')
        if self.severities and self.scanner_key != '7':
            raise ValueError('Severity filters are supported only by Nuclei')
        ceiling = {'7': 2, '8': 3, '9': 2}.get(self.scanner_key)
        if self.rate_limit is not None and (ceiling is None or type(self.rate_limit) is not int
                                             or not 1 <= self.rate_limit <= ceiling):
            raise ValueError('Request rate must reduce or preserve the built-in scanner limit')

    def to_dict(self) -> dict:
        value = asdict(self)
        value['ports'] = list(self.ports)
        value['severities'] = list(self.severities)
        return value

    @classmethod
    def from_dict(cls, value: dict) -> ScannerConfiguration:
        if not isinstance(value, dict) or set(value) - {
                'scanner_key', 'timeout_seconds', 'ports', 'severities', 'rate_limit'}:
            raise ValueError('Unknown scanner configuration fields')
        fields = dict(value)
        for name in ('ports', 'severities'):
            if name in fields:
                if not isinstance(fields[name], list):
                    raise ValueError('Scanner option must be an array')
                fields[name] = tuple(fields[name])
        try:
            return cls(**fields)
        except TypeError as exc:
            raise ValueError('Invalid scanner configuration') from exc
