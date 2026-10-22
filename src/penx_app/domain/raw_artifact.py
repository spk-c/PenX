"""Small validated reference to an optional separately retained raw capture."""
from dataclasses import dataclass
import re

MAX_ARTIFACT_BYTES = 1_048_576


@dataclass(frozen=True)
class RawArtifact:
    sha256: str
    size_bytes: int
    filename: str
    validator: str = "sha256-utf8-v1"

    def __post_init__(self):
        if not isinstance(self.sha256, str) or not re.fullmatch(r"[a-f0-9]{64}", self.sha256):
            raise ValueError("Invalid raw artifact hash")
        if type(self.size_bytes) is not int or not 0 <= self.size_bytes <= MAX_ARTIFACT_BYTES:
            raise ValueError("Invalid raw artifact size")
        if (not isinstance(self.filename, str) or not re.fullmatch(
                re.escape(self.sha256) + r"(?:_(?:\d{1,3}|[a-f0-9]{32}))?\.txt", self.filename)):
            raise ValueError("Invalid raw artifact filename")
        if self.validator != "sha256-utf8-v1":
            raise ValueError("Unknown raw artifact validator")
