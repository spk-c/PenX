"""Conservative in-memory evidence provenance tied to real scanner output.

A record is never inferred from historic presentation text or model claims.
The original scanner text must be supplied again to validate a record.
Persisted evidence schemas and report reference formats remain unchanged.
"""
from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Iterable
import hashlib

from penx_app.domain.scan_models import ScanResult, ScannerResult


@dataclass(frozen=True)
class EvidenceRecord:
    scanner_id: str
    kind: str
    parser_version: int
    raw_start: int
    raw_end: int
    quote: str
    host: str | None = None
    port: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.scanner_id, str) or not self.scanner_id:
            raise ValueError("Evidence scanner ID is required")
        if not isinstance(self.kind, str) or not self.kind or len(self.kind) > 40:
            raise ValueError("Invalid evidence kind")
        if type(self.parser_version) is not int or self.parser_version < 1:
            raise ValueError("Evidence parser version must be positive")
        if (type(self.raw_start) is not int or type(self.raw_end) is not int
                or self.raw_start < 0 or self.raw_end <= self.raw_start
                or self.raw_end - self.raw_start > 2000):
            raise ValueError("Evidence source range is invalid or too large")
        if not isinstance(self.quote, str) or not self.quote or len(self.quote) > 2000:
            raise ValueError("Evidence quote must be present and bounded")
        if len(self.quote) != self.raw_end - self.raw_start:
            raise ValueError("Evidence quote length must match its source range")
        if self.host is not None and (
                not isinstance(self.host, str) or len(self.host) > 253
                or not self.host):
            raise ValueError("Invalid optional evidence host")
        if self.port is not None and (type(self.port) is not int
                                      or not 1 <= self.port <= 65535):
            raise ValueError("Invalid optional evidence port")

    def matches(self, scanner: ScannerResult) -> bool:
        """Validate exact evidence against the *same* trusted adapter text."""
        return (scanner.scanner_id == self.scanner_id
                and scanner.evidence and scanner.status != "FAILED"
                and self.raw_end <= len(scanner.text)
                and scanner.text[self.raw_start:self.raw_end] == self.quote)

    def source_ref(self) -> str:
        """Stable in-memory locator; not a claim about persisted raw evidence."""
        checksum = hashlib.sha256(self.quote.encode("utf-8")).hexdigest()[:12]
        return f"adapter:{self.scanner_id}:{self.raw_start}-{self.raw_end}:{checksum}"


def capture_evidence(scanner: ScannerResult, start: int, end: int, *,
                     kind: str, parser_version: int,
                     host: str | None = None,
                     port: int | None = None) -> EvidenceRecord:
    """Require real adapter evidence and capture a bounded exact raw slice."""
    if not scanner.evidence or scanner.status == "FAILED":
        raise ValueError("An unavailable scanner cannot supply evidence")
    if type(start) is not int or type(end) is not int:
        raise ValueError("Evidence offsets must be integers")
    if start < 0 or end > len(scanner.text) or end <= start:
        raise ValueError("Evidence offsets are outside the adapter's raw output")
    record = EvidenceRecord(
        scanner_id=scanner.scanner_id,
        kind=kind, parser_version=parser_version,
        raw_start=start, raw_end=end, quote=scanner.text[start:end],
        host=host, port=port,
    )
    if not record.matches(scanner):
        raise ValueError("Evidence no longer matches its source")
    return record


def revalidate_persisted_evidence(
    stored: ScanResult, original_sources: Iterable[ScannerResult],
) -> tuple[EvidenceRecord, ...]:
    """Check historical anchors against independently supplied raw adapter results.

    Scan metadata contains quotes and offsets, NOT the original source text.
    Callers must obtain trusted adapter results from a separately retained raw
    capture. Passing a restored ScanResult is not enough: its text is empty.
    A missing, failed, duplicated, or mismatched source fails closed. A
    successful match attests only that the quoted slice exists in the supplied
    source; it does not prove CVE applicability or network target identity.
    """
    sources: dict[str, ScannerResult] = {}
    for result in original_sources:
        if result.scanner_id in sources:
            raise ValueError("Duplicate original scanner ID during evidence revalidation")
        sources[result.scanner_id] = result

    verified: list[EvidenceRecord] = []
    for adapter in stored.results:
        if not adapter.evidence_records:
            continue
        original = sources.get(adapter.scanner_id)
        if original is None:
            raise ValueError("Original scanner output missing for persisted evidence")
        for record in adapter.evidence_records:
            if not record.matches(original):
                raise ValueError("Persisted evidence does not match original scanner output")
            verified.append(record)
    return tuple(verified)
