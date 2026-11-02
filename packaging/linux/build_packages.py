#!/usr/bin/env python3
"""Package a previously built Linux onedir executable as tar.gz and Debian .deb.

No scripts run on install, no dependency downloads, no postinst actions.
The Debian installation marks the executable as installed so per-user data
is written to XDG_DATA_HOME/PenX rather than /opt.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "dist" / "PenX"
OUT = ROOT / "artifacts"
ARCHES = {"x86_64": "amd64", "aarch64": "arm64"}


def release_version() -> str:
    source = (ROOT / "src" / "penx_app" / "version.py").read_text(encoding="utf-8")
    match = re.search(r'^VERSION\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"\s*$', source, re.M)
    if not match:
        raise ValueError("Missing safe semver in penx_app/version.py")
    return match.group(1)


def build_packages(*, output_dir: Path = OUT) -> list[Path]:
    executable = BUILD / "PenX"
    if not executable.is_file():
        raise FileNotFoundError("Run python scripts/build_linux.py first")
    if not executable.stat().st_mode & 0o111:
        raise ValueError("PenX is not executable")
    arch = ARCHES.get(platform.machine().lower())
    if not arch:
        raise ValueError(f"Unsupported target architecture: {platform.machine()}")
    version = release_version()
    output_dir.mkdir(parents=True, exist_ok=True)
    tar_path = output_dir / f"PenX-Linux-{platform.machine().lower()}.tar.gz"
    with tarfile.open(tar_path, "w:gz") as archive:
        archive.add(BUILD, arcname="PenX", recursive=True)
    deb_path = output_dir / f"penx_{version}_{arch}.deb"
    with tempfile.TemporaryDirectory(prefix="penx-deb-") as temporary:
        stage = Path(temporary) / "penx"
        destination = stage / "opt" / "penx" / "PenX"
        shutil.copytree(BUILD, destination, symlinks=False)
        (destination / ".penx-installed").write_text(
            "Installed with the PenX Debian package.\n", encoding="utf-8"
        )
        launcher = stage / "usr" / "bin" / "penx"
        launcher.parent.mkdir(parents=True, exist_ok=True)
        launcher.write_text(
            '#!/bin/sh\nexec /opt/penx/PenX/PenX "$@"\n',
            encoding="utf-8",
        )
        launcher.chmod(0o755)
        control = stage / "DEBIAN" / "control"
        control.parent.mkdir(parents=True, exist_ok=True)
        control.write_text(
            f"Package: penx\nVersion: {version}\nSection: utils\n"
            f"Priority: optional\nArchitecture: {arch}\n"
            "Maintainer: PenX contributors <noreply@github.com>\n"
            "Depends: libc6, libstdc++6, zlib1g\n"
            "Description: PenX defensive security reconnaissance with local AI\n"
            " Evidence-based local security assessment CLI for authorized targets.\n"
            " Third-party scanners and local AI models are not included.\n",
            encoding="utf-8",
        )
        control.chmod(0o644)
        subprocess.run(["dpkg-deb", "--build", "--root-owner-group",
                        str(stage), str(deb_path)], check=True)
    return [tar_path, deb_path]


def main() -> int:
    parser = argparse.ArgumentParser(description="Package PenX for Linux")
    parser.add_argument("--output", type=Path, default=OUT)
    args = parser.parse_args()
    for path in build_packages(output_dir=args.output):
        print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
