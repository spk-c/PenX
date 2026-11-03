"""Bounded opt-in reference to scanner subprocess stdout *before* decoding."""
from __future__ import annotations

from dataclasses import dataclass
import re

from penx_app.domain.raw_artifact import MAX_ARTIFACT_BYTES


@dataclass(frozen=True)
class StdoutByteCapture:
    sha256: str
    size_bytes: int
    filename: str
    text_sha256: str
    validator: str = "sha256-predecode-stdout-v1"

    def __post_init__(self) -> None:
        if (not isinstance(self.sha256, str)
                or not re.fullmatch(r"[a-f0-9]{64}", self.sha256)):
            raise ValueError("Invalid stdout byte digest")
        if (type(self.size_bytes) is not int
                or not 1 <= self.size_bytes <= MAX_ARTIFACT_BYTES):
            raise ValueError("Invalid stdout byte size")
        if (not isinstance(self.filename, str)
                or not re.fullmatch(
                    re.escape(self.sha256) + r"(?:_(?:\d{1,3}|[a-f0-9]{32}))?\.bin",
                    self.filename)):
            raise ValueError("Invalid stdout byte filename")
        if (not isinstance(self.text_sha256, str)
                or not re.fullmatch(r"[a-f0-9]{64}", self.text_sha256)):
            raise ValueError("Invalid stdout decoded-text digest")
        if self.validator != "sha256-predecode-stdout-v1":
            raise ValueError("Unknown stdout byte validator")
