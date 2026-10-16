"""Publish verified tag builds from the GitLab generic registry as release assets.

Only invoked by a tag CI job after the Windows packaging job succeeded.
Requires CI_JOB_TOKEN; does not send tokens to logs.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
from urllib.error import HTTPError
from urllib.request import Request, urlopen

FILES = ("PenX-Setup-x64.exe", "PenX-Windows-x64.zip", "SHA256SUMS.txt")
TAG = re.compile(r"^v\d+\.\d+\.\d+$")


def main() -> int:
    tag = os.environ.get("CI_COMMIT_TAG", "")
    api = os.environ.get("CI_API_V4_URL", "")
    project = os.environ.get("CI_PROJECT_ID", "")
    token = os.environ.get("CI_JOB_TOKEN", "")
    if not TAG.fullmatch(tag) or not api.startswith("https://gitlab.com/api/v4") or not project.isdigit() or not token:
        raise RuntimeError("Refusing release outside an authenticated GitLab tag pipeline")
    root = Path("dist")
    for name in FILES:
        if not (root / name).is_file():
            raise RuntimeError(f"Missing verified release asset: {name}")
    checksum = (root / "SHA256SUMS.txt").read_text(encoding="ascii")
    for name in FILES[:2]:
        expected = hashlib.sha256((root / name).read_bytes()).hexdigest()
        if f"{expected}  {name}" not in checksum.splitlines():
            raise RuntimeError(f"Checksum mismatch for {name}")
    links = [
        {
            "name": name,
            "url": f"{api}/projects/{project}/packages/generic/penx/{tag}/{name}",
            "direct_asset_path": f"/{name}",
            "link_type": "package",
        }
        for name in FILES
    ]
    payload = {
        "name": f"PenX {tag}",
        "tag_name": tag,
        "description": (
            "Verified Windows installer and portable build. Download the "
            "installer, portable ZIP and SHA256SUMS.txt from this release. "
            "Scanner dependencies and local AI models are not bundled. "
            "Authorized security assessment only."
        ),
        "assets": {"links": links},
    }
    url = f"{api}/projects/{project}/releases"
    req = Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"JOB-TOKEN": token, "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(req, timeout=30) as response:
            result = json.load(response)
    except HTTPError as exc:
        raise RuntimeError(f"GitLab release creation failed (HTTP {exc.code})") from None
    if result.get("tag_name") != tag:
        raise RuntimeError("GitLab release response did not confirm the tag")
    print(f"GitLab release published: {tag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
